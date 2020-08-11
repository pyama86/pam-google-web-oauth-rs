extern crate syslog;
#[macro_use]
extern crate log;

#[macro_use]
extern crate pam;
use libc::c_char;
use pam::constants::{PamFlag, PamItemType, PamResultCode, PAM_PROMPT_ECHO_OFF, PAM_RHOST};
use pam::conv::PamConv;
use pam::module::{PamHandle, PamHooks, PamResult};
use std::collections::HashMap;
use std::ffi::CStr;
use std::ptr;

use anyhow::{format_err, Context, Result};
use failure::Fail;
use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::reqwest::{http_client, HttpClientError};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest, HttpResponse,
    PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use log::LevelFilter;
use syslog::{BasicLogger, Facility, Formatter3164};

#[test]
use http::header::{HeaderValue, CONTENT_TYPE};
#[test]
use http::status::StatusCode;

macro_rules! pam_try {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    ($e:expr, $err:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => {
                error!("Error: {}", e);
                return $err;
            }
        }
    };
}

struct PamOAuth;
pam_hooks!(PamOAuth);

impl PamHooks for PamOAuth {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "pam-google-web-oauth".into(),
            pid: 0,
        };

        let logger = syslog::unix(formatter).expect("could not connect to syslog");
        let _ = log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
            .map(|()| log::set_max_level(LevelFilter::Info));

        let args: Vec<_> = args
            .iter()
            .map(|s| s.to_string_lossy().to_owned())
            .collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, "=");
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let user = pam_try!(pamh.get_user(None));
        let client_ip = pam_try!(get_rhost(pamh, None));

        let client_id: &str = match args.get("client_id") {
            Some(client_id) => client_id,
            None => {
                error!("parameter client_id is required ");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };
        let client_secret: &str = match args.get("client_secret") {
            Some(client_secret) => client_secret,
            None => {
                error!("parameter client_secret is required ");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };
        let user_dir: &str = match args.get("user_dir") {
            Some(user_dir) => user_dir,
            None => {
                error!("parameter user_dir is required ");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        if !Path::new(user_dir).exists() {
            let _ = std::fs::create_dir_all(user_dir);
            let _ = std::fs::set_permissions(user_dir, PermissionsExt::from_mode(0o700));
        }

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                return err;
            }
        };
        let user_file_path: String;
        let u = Path::new(user_dir).join(format!("{}.json", user));

        match u.to_str() {
            Some(u) => user_file_path = u.to_string(),
            None => return PamResultCode::PAM_AUTH_ERR,
        }

        let client = get_client(client_id, client_secret);
        if let Ok(_) = auth_with_cache(&user_file_path, &client_ip, &client, http_client) {
            return PamResultCode::PAM_SUCCESS;
        }

        match auth(&user_file_path, &client_ip, &client, conv, http_client) {
            Ok(_) => {
                return PamResultCode::PAM_SUCCESS;
            }
            Err(err) => {
                error!("oauth authenticate error:{}", &err.to_string());
            }
        }
        PamResultCode::PAM_AUTH_ERR
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn get_client(client_id: &str, client_secret: &str) -> BasicClient {
    let google_client_id = ClientId::new(client_id.to_string());
    let google_client_secret = ClientSecret::new(client_secret.to_string());
    let auth_url = AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
        .expect("Invalid authorization endpoint URL");
    let token_url = TokenUrl::new("https://www.googleapis.com/oauth2/v3/token".to_string())
        .expect("Invalid token endpoint URL");

    BasicClient::new(
        google_client_id,
        Some(google_client_secret),
        auth_url,
        Some(token_url),
    )
    .set_redirect_url(
        RedirectUrl::new("urn:ietf:wg:oauth:2.0:oob".to_string()).expect("Invalid redirect URL"),
    )
}

fn auth_with_cache(
    user_file_path: &String,
    ip: &String,
    client: &BasicClient,
    http_client: fn(HttpRequest) -> Result<HttpResponse, HttpClientError>,
) -> Result<()> {
    let token_cache = load_from_file(&user_file_path);
    match token_cache {
        Some(token_cache) => {
            if &token_cache.last_ip == ip {
                let refresh_token = token_cache.token.refresh_token();
                if let Some(refresh_token) = refresh_token {
                    let token = client
                        .exchange_refresh_token(refresh_token)
                        .request(http_client);

                    if let Ok(mut token) = token {
                        if token.access_token().secret()
                            != token_cache.token.access_token().secret()
                        {
                            token.set_refresh_token(Some(refresh_token.to_owned()));
                            return save_file(user_file_path, ip, &token);
                        }
                        return Ok(());
                    }
                }
            }
        }
        None => {}
    }
    Err(format_err!("authentication failed"))
}

fn display_auth_url(
    client: &BasicClient,
    conv: &PamConv,
    pkce_code_challenge: oauth2::PkceCodeChallenge,
) -> Result<AuthorizationCode> {
    let (authorize_url, _csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_code_challenge)
        .url();

    if let Ok(s) = conv.send(PAM_PROMPT_ECHO_OFF, &format!(
                "Go to the following link in your browser then type the authorization code: \n\n{}\n\nPlease type code:",
                authorize_url.to_string())) {
        match s {
            Some(s) =>  Ok(AuthorizationCode::new(s)),
            None => return Err(format_err!("can't get auth code")),
        }
    } else {
        return Err(format_err!("can't get auth code"));
    }
}

fn auth_with_code(
    user_file_path: &String,
    ip: &String,
    client: &BasicClient,
    code: AuthorizationCode,
    pkce_code_verifier: oauth2::PkceCodeVerifier,
    http_client: fn(HttpRequest) -> Result<HttpResponse, HttpClientError>,
) -> Result<()> {
    let token = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_code_verifier)
        .request(http_client);
    match token {
        Ok(token) => {
            return save_file(user_file_path, ip, &token);
        }
        Err(err) => match err {
            oauth2::RequestTokenError::ServerResponse(err) => {
                let err_string = err
                    .error_description()
                    .map(|s| s.clone())
                    .unwrap_or(format!("{:?}", err.error()));
                Err(format_err!(err_string)).context("Returned error by server")
            }
            oauth2::RequestTokenError::Request(err) => {
                Err(err.compat()).context("Failed to send/recv request")
            }
            oauth2::RequestTokenError::Parse(err, _data) => {
                Err(err).context("Failed to parse JSON response")
            }
            oauth2::RequestTokenError::Other(err) => {
                Err(format_err!(err)).context("Unexpected response")
            }
        },
    }
}

fn auth(
    user_file_path: &String,
    client_ip: &String,

    client: &BasicClient,
    conv: &PamConv,
    http_client: fn(HttpRequest) -> Result<HttpResponse, HttpClientError>,
) -> Result<()> {
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();
    match display_auth_url(client, conv, pkce_code_challenge) {
        Ok(code) => {
            return auth_with_code(
                user_file_path,
                client_ip,
                client,
                code,
                pkce_code_verifier,
                http_client,
            );
        }
        Err(err) => {
            return Err(err);
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenCache {
    token: BasicTokenResponse,
    last_ip: String,
}

fn save_file(
    user_file_path: &String,
    client_ip: &String,
    token: &BasicTokenResponse,
) -> Result<()> {
    let cache = TokenCache {
        token: token.clone(),
        last_ip: client_ip.clone(),
    };

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(user_file_path);

    if let Ok(file) = file {
        serde_json::to_writer(&file, &cache)?;
    }

    let _ = std::fs::set_permissions(user_file_path, PermissionsExt::from_mode(0o700));

    Ok(())
}

fn load_from_file(name: &String) -> Option<TokenCache> {
    let file = File::open(name);
    if let Ok(file) = file {
        let reader = BufReader::new(file);

        let deserialized = serde_json::from_reader(reader);
        if let Ok(deserialized) = deserialized {
            return Some(deserialized);
        }
    }
    None
}

#[test]
fn test_load_from_file() {
    let token = load_from_file(&"./misc/example.json".to_string()).unwrap();
    let serialized_json = serde_json::to_string(&token.token).unwrap();
    assert_eq!(
        "{\"access_token\":\"access\",\"token_type\":\"bearer\",\"expires_in\":3599,\"refresh_token\":\"refresh\",\"scope\":\"https://www.googleapis.com/auth/userinfo.profile\"}".to_string(),
        serialized_json
    );

    let notfound = load_from_file(&"./misc/notfound.json".to_string());
    assert!(notfound.is_none())
}

#[test]
fn test_save_file() {
    let json = "{\"access_token\":\"access\",\"token_type\":\"bearer\",\"expires_in\":3599,\"refresh_token\":\"refresh\",\"scope\":\"https://www.googleapis.com/auth/userinfo.profile\"}";
    let deserialized_token = serde_json::from_str::<BasicTokenResponse>(json).unwrap();

    let ret = save_file(&"/tmp/test_result.json".to_string(), &deserialized_token);
    assert!(ret.is_ok());
    assert_eq!(Path::new("/tmp/test_result.json").exists(), true);
}

#[test]
fn new_client() -> BasicClient {
    BasicClient::new(
        ClientId::new("aaa".to_string()),
        Some(ClientSecret::new("bbb".to_string())),
        AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
        Some(TokenUrl::new("https://example.com/token".to_string()).unwrap()),
    )
}

#[test]
fn mock_f(request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
    assert_eq!(
        String::from_utf8(request.body).unwrap(),
        "grant_type=refresh_token&refresh_token=refresh".to_string()
    );

    Ok(HttpResponse {
        status_code: StatusCode::OK,
        headers: vec![(
            CONTENT_TYPE,
            HeaderValue::from_str("APPLICATION/jSoN").unwrap(),
        )]
        .into_iter()
        .collect(),
        body: "{\
                \"access_token\": \"changed\", \
                \"token_type\": \"bearer\" \
              }"
        .to_string()
        .into_bytes(),
    })
}
#[test]
fn test_auth_with_cache_exists() {
    let token = load_from_file(&"./misc/example.json".to_string()).unwrap();
    save_file(&"./tmp/auth_with_cache.json".to_string(), &token.token).unwrap();

    env::set_var("SSH_CONNECTION", "1.1.1.1 56180 2.2.2.2 22");
    let r = auth_with_cache(
        &"./tmp/auth_with_cache.json".to_string(),
        &new_client(),
        mock_f,
    );

    let after = load_from_file(&"./tmp/auth_with_cache.json".to_string()).unwrap();
    let serialized_json = serde_json::to_string(&after.token).unwrap();

    assert_eq!(
        "{\"access_token\":\"changed\",\"token_type\":\"bearer\",\"refresh_token\":\"refresh\"}",
        serialized_json
    );
    assert!(r.is_ok());

    save_file(
        &"./tmp/auth_with_cache_unmatch_ip.json".to_string(),
        &token.token,
    )
    .unwrap();

    env::set_var("SSH_CONNECTION", "2.2.2.2 56180 2.2.2.2 22");
    let rr = auth_with_cache(
        &"./tmp/auth_with_cache_unmatch_ip.json".to_string(),
        &new_client(),
        mock_f,
    );

    assert!(rr.is_err());
}

#[link(name = "pam")]
extern "C" {
    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: PamItemType,
        val: &*mut c_char,
    ) -> PamResultCode;
}
pub fn get_rhost(pamh: &PamHandle, _prompt: Option<&str>) -> PamResult<String> {
    let ptr: *mut c_char = ptr::null_mut();
    let res = unsafe { pam_get_item(pamh, PAM_RHOST, &ptr) };
    if PamResultCode::PAM_SUCCESS == res && !ptr.is_null() {
        let const_ptr = ptr as *const c_char;
        let bytes = unsafe { CStr::from_ptr(const_ptr).to_bytes() };
        String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_CONV_ERR)
    } else {
        Err(res)
    }
}
