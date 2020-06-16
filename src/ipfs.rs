use std::path::{PathBuf, Path};
use crate::config::Config;
use crate::operation::Error;
use std::{fs, env, io, process};
use log::{error, info, warn};
use std::sync::{RwLock, Mutex, Arc};
use std::collections::{HashSet, HashMap};
use bytes::Bytes;
use rpki::uri;
use crate::metrics::IpfsModuleMetrics;
use std::time::SystemTime;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpnsPubkey(pub String);
impl IpnsPubkey {
    pub fn value(&self) -> &String {
        &self.0
    }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TalPubkey(pub String);
impl TalPubkey {
    pub fn value(&self) -> &String {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpfsPath(pub PathBuf);
impl IpfsPath {
    pub fn value(&self) -> &PathBuf {
        &self.0
    }

    pub fn to_string(&self) -> String {
        String::from(&self.0.display().to_string())
    }
}

#[derive(Clone, Debug)]
pub struct Cid(pub String);
impl Cid {
    pub fn to_string(&self) -> String {
        String::from(&self.0)
    }
}

#[derive(Clone, Debug)]
pub struct KeyName(pub String);
impl KeyName {
    pub fn to_string(&self) -> String {
        String::from(&self.0)
    }
}


#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    base_dir: CacheDir,

    /// The backing storage of ipfs.
    ipfs_path: Option<IpfsPath>,

    /// Hash of ipns public key to publish to
    ipns_pubkey: Option<IpnsPubkey>,

    /// The command for running ipfs.
    ///
    /// If this is `None` actual ipfs has been disabled.
    command: Option<Command>,
}

impl Cache {
    // Takes care of creating the directory/file system
    pub fn init(config: &Config) -> Result<(), Error> {
        let ipfs_dir = Self::cache_dir(config);
        if let Err(err) = fs::create_dir_all(&ipfs_dir) {
            error!(
                "Failed to create IPFS cache directory {}: {}.",
                ipfs_dir.display(), err
            );
            return Err(Error);
        }
        Ok(())
    }

    pub fn new(config: &Config, update: bool) -> Result<Option<Self>, Error> {
        if config.disable_ipfs {
            Ok(None)
        }
        else {
            Self::init(config)?;
            Ok(Some(Cache {
                base_dir: CacheDir::new(Self::cache_dir(config)),
                command: if update {
                    Some(Command::new(config)?)
                } else {
                    None
                },
                ipfs_path: config.ipfs_path.clone(),
                ipns_pubkey: config.ipns_pubkey.clone()
            }))
        }
    }

    pub fn start(&self) -> Result<Run, Error> {
        Run::new(self)
    }

    pub fn ipfs_path(&self) -> Option<IpfsPath> {
        self.ipfs_path.clone()
    }

    pub fn ipns_pubkey(&self) -> Option<IpnsPubkey> {
        self.ipns_pubkey.clone()
    }

    pub fn local_repo_dir(&self, uri: &uri::Ipns) -> PathBuf {
        let mut res = self.base_dir.base.clone();
        res.push(uri.get_repo_publish_key());
        res
    }

    pub fn local_ta_cer_dir(&self, uri: &uri::Ipns) -> PathBuf {
        let mut res = self.base_dir.base.clone();
        res.push(uri.get_ta_publish_key());
        res
    }

    fn cache_dir(config: &Config) -> PathBuf {
        config.cache_dir.join("ipfs")
    }
}




#[derive(Clone, Debug)]
struct CacheDir {
    base: PathBuf
}

impl CacheDir {
    fn new(base: PathBuf) -> Self {
        CacheDir { base }
    }
}



/// Information for a validation run.
#[derive(Debug)]
pub struct Run<'a> {
    /// A reference to the underlying cache.
    cache: &'a Cache,
    updated: RwLock<HashSet<uri::RsyncModule>>,
    running: RwLock<HashMap<uri::RsyncModule, Arc<Mutex<()>>>>,
    metrics: Mutex<Vec<IpfsModuleMetrics>> //TODO DA: Add IPS module
}

impl<'a> Run<'a>  {
    pub fn new(cache: &'a Cache) -> Result<Self, Error> {
        Ok(Run {
            cache,
            updated: Default::default(),
            running: Default::default(),
            metrics: Default::default(),
        })
    }

    pub fn cache(&self) -> &Cache {
        self.cache
    }

    pub fn sync(&self, ipfs_path: &IpfsPath, uri: &uri::Ipns) {
        println!("Starting syncing IPFS...");
        env::set_var("IPFS_PATH", ipfs_path.to_string());

        let source = format!("/ipns/{}", &uri.get_repo_publish_key());

        let destination = &self.cache.local_repo_dir(uri);

        let destination = format!("--output={}", destination.display().to_string());

        let result = std::process::Command::new("ipfs")
            .arg("get")
            .arg(source)
            .arg(destination)
            .output().expect("could not sync ipfs");

        println!("Finished syncing IPFS...");
        env::set_var("IPFS_PATH", "");
        println!("{:?}", result);
    }

    pub fn load_ta(&self, uri: &uri::Ipns) {
        let command = match self.cache.command.as_ref() {
            Some(command) => command,
            None => return,
        };

        // Run the actual update.
        let metrics = command.fetch_ta_cer_to_local(
            uri, &self.cache
        );

        // Insert into updated map and metrics.
        self.metrics.lock().unwrap().push(metrics);
    }

    pub fn do_load_file_from_cache(&self, rsync_uri: &uri::Rsync, ipns_uri: &uri::Ipns) -> Option<Bytes> {
        let source = self.cache
            .base_dir
            .base
            .join(&rsync_uri.to_ipns_repo_path(ipns_uri));

        match fs::File::open(&source) {
            Ok(mut file) => {
                let mut data = Vec::new();
                if let Err(err) = io::Read::read_to_end(&mut file, &mut data) {
                    warn!(
                        "Failed to read file '{}': {}",
                        source.display(),
                        err
                    );
                    None
                }
                else {
                    Some(data.into())
                }
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    info!("{}: not found in local ipfs repository", source.display());
                } else {
                    warn!(
                        "Failed to open file '{}': {}",
                        source.display(), err
                    );
                }
                None
            }
        }
    }

    pub fn load_ta_file_from_cache(
        &self,
        uri: &uri::Ipns,
    ) -> Option<Bytes> {
        let path = self.cache.local_ta_cer_dir(uri).join("ta.cer");
        match fs::File::open(&path) {
            Ok(mut file) => {
                let mut data = Vec::new();
                if let Err(err) = io::Read::read_to_end(&mut file, &mut data) {
                    warn!(
                        "Failed to read file '{}': {}",
                        path.display(),
                        err
                    );
                    None
                }
                else {
                    Some(data.into())
                }
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    info!("{}: not found in local ipfs repository", uri);
                } else {
                    warn!(
                        "Failed to open file '{}': {}",
                        path.display(), err
                    );
                }
                None
            }
        }
    }

}

/// The command to run ipfs.
#[derive(Debug)]
struct Command {
    command: String,
    args: Vec<String>,
}

impl Command {
    pub fn new(config: &Config) -> Result<Self, Error> {
        let command = config.ipfs_command.clone();
        let args = vec![String::from("")];
        Ok(Command {
            command,
            args,
        })
    }

    pub fn fetch_ta_cer_to_local(
        &self,
        source: &uri::Ipns,
        destination: &Cache
    ) -> IpfsModuleMetrics {
        let start = SystemTime::now();
        let status = {
            match self.fetch_ta_cer(&source, destination) {
                Ok(mut command) => match command.output() {
                    Ok(output) => Ok(Self::log_output(&source.as_str().to_string(), output)),
                    Err(err) => Err(err)
                }
                Err(err) => Err(err)
            }
        };
        IpfsModuleMetrics {
            ipns: source.clone(),
            status,
            duration: SystemTime::now().duration_since(start),
        }
    }

    // TODO DA Check destination - should be in the directory created for the repo
    // TODO DA check if this can be reused for fetching the repo
    fn fetch_ta_cer(
        &self,
        source: &uri::Ipns,
        cache: &Cache
    ) -> Result<process::Command, io::Error> {
        let destination = cache.local_ta_cer_dir(source);
        fs::create_dir_all(&destination)?;

        let mut cmd = process::Command::new(&self.command);

        let destination = format!("--output={}/ta.cer", &destination.display().to_string());
        let source = format!("/ipns/{}", source.get_ta_publish_key());
        dbg!(&source);
        dbg!(&destination);
        cmd.arg("get")
            .arg(source)
            .arg(destination);

        info!("ipfs Running command {:?}", cmd);

        Ok(cmd)
    }


    fn log_output(
        source: &String,
        output: process::Output
    ) -> process::ExitStatus {
        if !output.status.success() {
            warn!(
                "ipfs to retrieve cid {} failed with status {}",
                source, output.status
            );
        }
        else {
            info!(
                "successfully completed {}.",
                source,
            );
        }
        // if !output.stderr.is_empty() {
        //     String::from_utf8_lossy(&output.stderr).lines().for_each(|l| {
        //         warn!(
        //             "rsync://{}/{}: {}", source.authority(), source.module(), l
        //         );
        //     })
        // }
        // if !output.stdout.is_empty() {
        //     String::from_utf8_lossy(&output.stdout).lines().for_each(|l| {
        //         info!(
        //             "rsync://{}/{}: {}", source.authority(), source.module(), l
        //         )
        //     })
        // }
        output.status
    }

    #[cfg(not(windows))]
    fn format_destination(path: &Path) -> Result<String, Error> {
        let mut destination = format!("{}", path.display());
        if !destination.ends_with('/') {
            destination.push('/')
        }
        Ok(destination)
    }

}