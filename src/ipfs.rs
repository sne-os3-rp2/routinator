use std::path::{PathBuf, Path};
use crate::config::Config;
use crate::operation::Error;
use std::{fs, env, io, process};
use log::{error, info, warn};
use std::sync::{RwLock, Mutex, Arc};
use std::collections::{HashSet, HashMap};
use std::process::Output;
use bytes::Bytes;
use rpki::uri;
use crate::metrics::IpfsModuleMetrics;
use std::time::SystemTime;

#[derive(Clone, Debug)]
pub struct IpnsPubkey {
    pub key: String
}

#[derive(Clone, Debug)]
pub struct IpfsPath {
    pub path: PathBuf
}

#[derive(Clone, Debug)]
pub struct Cid {
    pub value: String
}

#[derive(Debug)]
pub struct Cache {
    /// The base directory of the cache.
    base_dir: CacheDir,


    /// The backing storage of ipfs.
    /// TODO change this to its own type
    ipfs_path: PathBuf,

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
                // TODO DA is it necessary to create a new IpfsPath?
                ipfs_path: PathBuf::from(config.ipfs_path.clone())
            }))
        }
    }

    pub fn start(&self) -> Result<Run, Error> {
        Run::new(self)
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

    fn module_path(&self, module: &uri::RsyncModule) -> PathBuf {
        let mut res = self.base.clone();
        res.push(module.authority());
        res.push(module.module());
        res
    }

    fn uri_path(&self, uri: &uri::Rsync) -> PathBuf {
        let mut res = self.module_path(uri.module());
        res.push(uri.path());
        res
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

    pub fn sync(&self, public_key: &IpnsPubkey, ipfs_path: &IpfsPath, uri: &uri::Rsync) {
        println!("Starting syncing IPFS...");
        env::set_var("IPFS_PATH", ipfs_path.path.as_os_str());

        let source = format!("/ipns/{}", &public_key.key);

        let module = uri.module();
        let destination = &self.cache.base_dir.module_path(module);

        let destination = format!("--output={}", destination.display().to_string());

        //let destination = String::from("/Users/oluwadadepoaderemi/.rpki-cache/repository/ipfs");
        // TODO DA this is repeated. extract
        let result = std::process::Command::new("ipfs")
            .arg("get")
            .arg(source)
            .arg(destination)
            .output().expect("gbege");

        println!("Finished syncing IPFS...");
        env::set_var("IPFS_PATH", "");
        println!("{:?}", result);
    }

    pub fn load_ta(&self, uri: &uri::Rsync) {
        let command = match self.cache.command.as_ref() {
            Some(command) => command,
            None => return,
        };
        let module = uri.module();

        // TODO DA move cid to config
        let ta_cer_cid = Cid { value: String::from("QmeHrf3ErtjSrcsk9YQTQE1JiwGhgp5MwUqnVWtu5VRuA2")};

        // If it is already up-to-date, return.
        if self.updated.read().unwrap().contains(module) {
            return
        }

        // Get a clone of the (arc-ed) mutex. Make a new one if there isn’t
        // yet.
        let mutex = {
            self.running.write().unwrap()
                .entry(module.clone()).or_default()
                .clone()
        };

        // Acquire the mutex. Once we have it, see if the module is up-to-date
        // which happens if someone else had it first.
        let _lock = mutex.lock().unwrap();
        if self.updated.read().unwrap().contains(module) {
            return
        }

        // Run the actual update.
        let metrics = command.update(
            ta_cer_cid, &self.cache.base_dir.module_path(module)
        );

        // Insert into updated map and metrics.
        self.metrics.lock().unwrap().push(metrics);

        // Insert into updated map no matter what.
        self.updated.write().unwrap().insert(module.clone());

        // Remove from running.
        self.running.write().unwrap().remove(module);
    }

    pub fn load_file(
        &self,
        uri: &uri::Rsync,
    ) -> Option<Bytes> {
        let path = self.cache.base_dir.uri_path(uri);
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

    pub fn update(
        &self,
        source: Cid,
        destination: &Path
    ) -> IpfsModuleMetrics {
        let start = SystemTime::now();
        let status = {
            match self.command(&source, destination) {
                Ok(mut command) => match command.output() {
                    Ok(output) => Ok(Self::log_output(&source, output)),
                    Err(err) => Err(err)
                }
                Err(err) => Err(err)
            }
        };
        IpfsModuleMetrics {
            cid: source.clone(),
            status,
            duration: SystemTime::now().duration_since(start),
        }
    }

    fn command(
        &self,
        source: &Cid,
        destination: &Path
    ) -> Result<process::Command, io::Error> {
        info!("ipfs retrieve cid: {}.", source.value);
        fs::create_dir_all(destination)?;
        let destination = match Self::format_destination(destination) {
            Ok(some) => some,
            Err(_) => {
                error!(
                    "ipfs: illegal destination path {}.",
                    destination.display()
                );
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "illegal destination path"
                ));
            }
        };
        let mut cmd = process::Command::new(&self.command);

        let destination = format!("--output={}ta.cer", destination);

        cmd.arg("get")
            .arg(source.value.clone())
            .arg(destination);
        info!(
            "ipfs Running command {:?}", cmd
        );
        Ok(cmd)
    }


    fn log_output(
        source: &Cid,
        output: process::Output
    ) -> process::ExitStatus {
        if !output.status.success() {
            warn!(
                "ipfs to retrieve cid {} failed with status {}",
                source.value, output.status
            );
        }
        else {
            info!(
                "successfully completed {}.",
                source.value,
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