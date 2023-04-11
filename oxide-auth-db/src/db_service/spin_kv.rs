use std::{convert::TryInto, borrow::Borrow};

use anyhow::Result;
use chrono::{prelude::*, Duration};
use oxide_auth::{primitives::{registrar::EncodedClient, prelude::{TagGrant, IssuedToken}, grant::Grant, issuer::{RefreshedToken, TokenType}}, endpoint::{Authorizer, Issuer}};
use serde::{Serialize, Deserialize};
use spin_sdk::key_value::{
    Error as KeyValueError,
    Store
};

use crate::primitives::db_registrar::OauthClientDBRepository;

trait JsonStore {
    fn store(&self) -> &Store;
    fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<T> {
        let value = self.store().get(key)?;
        let value = serde_json::from_slice(&value)?;
        Ok(value)
    }
    fn list_json<T: serde::de::DeserializeOwned>(&self) -> Result<Vec<T>> {
        let mut result = Vec::new();
        for key in self.store().get_keys()? {
            let value = self.get_json(&key)?;
            result.push(value);
        }
        Ok(result)
    }
    fn set_json<T: serde::Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let value = serde_json::to_vec(value)?;
        self.store().set(key, &value)?;
        Ok(())
    }
    fn get_u64(&self, key: &str) -> Result<u64> {
        let value = self.store().get(key)?;
        let value = u64::from_be_bytes(value
            .try_into()
            .map_err(|x| anyhow::anyhow!("Failed to convert usage to u64: {:?}", x))?);
        Ok(value)
    }
    fn set_u64(&self, key: &str, value: u64) -> Result<()> {
        let value: &[u8] = &value.to_be_bytes();
        self.store().set(key, value)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SpinKeyValueDataSource {
    store: std::rc::Rc<Store>,
}

impl JsonStore for SpinKeyValueDataSource {
    fn store(&self) -> &Store {
        &self.store
    }
}

impl SpinKeyValueDataSource {
    pub fn new(store_name: impl AsRef<str>) -> Result<Self, KeyValueError> {
        let store = Store::open(store_name)?;
        Ok(SpinKeyValueDataSource{
            store: std::rc::Rc::from(store),
        })
    }
}

impl OauthClientDBRepository for SpinKeyValueDataSource {
    fn list(&self) -> Result<Vec<EncodedClient>> {
        // collect into a result because there's some magic fookery here 
        // that I don't understand but I found it on SO and it looks coool
        Ok(self.list_json()?)
    }

    fn find_client_by_id(&self, id: &str) -> Result<EncodedClient> {
        Ok(self.get_json(id)?)
    }

    fn regist_from_encoded_client(&self, client: EncodedClient) -> Result<()> {
        self.set_json(&client.client_id, &client)?;
        Ok(())
    }
}

pub struct SpinKeyValueAuthorizer<I: TagGrant = Box<dyn TagGrant>> {
    store: std::rc::Rc<Store>,
    tagger: I,
}

impl<I: TagGrant> JsonStore for SpinKeyValueAuthorizer<I> {
    fn store(&self) -> &Store {
        &self.store
    }
}

impl<I: TagGrant> SpinKeyValueAuthorizer<I> {
    pub fn new(store_name: impl AsRef<str>, tagger: I) -> Result<Self, KeyValueError> {
        let store = Store::open(store_name)?;
        Ok(SpinKeyValueAuthorizer{
            store: std::rc::Rc::from(store),
            tagger,
        })
    }
}

impl Authorizer for SpinKeyValueAuthorizer {
    fn authorize(&mut self, grant: Grant) -> std::result::Result<String, ()> {
        //TODO: Handle errors
        let usage = self.get_u64("usage").map_err(|_| ())?;
        let next_usage = usage.wrapping_add(1);
        let token = self.tagger.tag(next_usage - 1, &grant)?;
        self.set_json(&token, &grant).map_err(|_| ())?;
        self.set_u64("usage", next_usage).map_err(|_| ())?;
        Ok(token)
    }

    fn extract(&mut self, token: &str) -> std::result::Result<Option<Grant>, ()> {
        //TODO: Handle errors
        // Get the grant from the store
        let grant = self.get_json(token).map_err(|_| ())?;
        // Delete the grant from the store
        self.store.delete(token).map_err(|_| ())?;
        Ok(grant)
    }
}

pub struct SpinKeyValueIssuer<G: TagGrant = Box<dyn TagGrant>> {
    store: std::rc::Rc<Store>,
    generator: G,
    duration: Option<Duration>,
}

impl<G: TagGrant> JsonStore for SpinKeyValueIssuer<G> {
    fn store(&self) -> &Store {
        &self.store
    }
}

impl<G: TagGrant> SpinKeyValueIssuer<G> {
    pub fn new(store_name: impl AsRef<str>, generator: G) -> Result<Self, KeyValueError> {
        let store = Store::open(store_name)?;
        Ok(SpinKeyValueIssuer{
            store: std::rc::Rc::from(store),
            generator,
            duration: None,
        })
    }

    fn set_duration(&self, grant: &mut Grant) {
        if let Some(duration) = &self.duration {
            grant.until = Utc::now() + *duration;
        }
    }
}

impl<G: TagGrant> Issuer for SpinKeyValueIssuer<G> {
    fn issue(&mut self, mut grant: Grant) -> std::result::Result<IssuedToken, ()> {
        self.set_duration(&mut grant);

        let usage = self.get_u64("usage").map_err(|_| ())?;
        let next_usage = usage.wrapping_add(2);

        let (access, refresh) = {
            let access = self.generator.tag(next_usage - 2, &grant)?;
            let refresh = self.generator.tag(next_usage - 1, &grant)?;
            debug_assert!(
                access.len() > 0,
                "An empty access token was generated, this is horribly insecure."
            );
            debug_assert!(
                refresh.len() > 0,
                "An empty refresh token was generated, this is horribly insecure."
            );
            (access, refresh)
        };

        let token = Token {
            access: access.clone(),
            refresh: Some(refresh.clone()),
            grant,
        };
        self.set_json(&access, &token).map_err(|_| ())?;
        self.set_json(&refresh, &token).map_err(|_| ())?;
        self.set_u64("usage", next_usage).map_err(|_| ())?;
        Ok(IssuedToken {
            token: access,
            refresh: Some(refresh),
            until: token.grant.until,
            token_type: TokenType::Bearer
        })
    }

    fn refresh(&mut self, refresh: &str, mut grant: Grant) -> std::result::Result<RefreshedToken, ()> {
        // Get the refresh token from the store
        let token: Token = self.get_json(refresh).map_err(|_| ())?;
        // Invalidate the previous refresh token
        self.store.delete(refresh).map_err(|_| ())?;

        assert!(refresh == token.refresh.unwrap());
        self.set_duration(&mut grant);

        let usage = self.get_u64("usage").map_err(|_| ())?;
        let new_access = self.generator.tag(usage, &grant)?;

        let usage = usage.wrapping_add(1);
        let new_refresh = self.generator.tag(usage, &grant)?;

        self.store.delete(&token.access).map_err(|_| ())?;
    }

    fn recover_token<'a>(&'a self, _: &'a str) -> std::result::Result<Option<Grant>, ()> {
        todo!()
    }

    fn recover_refresh<'a>(&'a self, _: &'a str) -> std::result::Result<Option<Grant>, ()> {
        todo!()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Token {
    access: String,
    refresh: Option<String>,
    grant: Grant,
}
