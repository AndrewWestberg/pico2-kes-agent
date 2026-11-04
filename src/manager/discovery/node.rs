use super::read_file;
use blake2::{Blake2b, Digest, digest::consts::U32};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KnownNetwork {
    Mainnet,
    Preprod,
    Preview,
    Custom(String),
}
#[derive(Clone, Debug)]
pub struct NodeCandidate {
    pub unit: String,
    pub config: Option<PathBuf>,
    pub byron: PathBuf,
    pub shelley: PathBuf,
    pub network: KnownNetwork,
    pub byron_epochs: Option<u64>,
    pub shelley_hash_matches: Option<bool>,
}

pub fn discover_nodes() -> Vec<NodeCandidate> {
    discover_nodes_in(&[
        Path::new("/etc/systemd/system"),
        Path::new("/usr/lib/systemd/system"),
        Path::new("/lib/systemd/system"),
    ])
}
pub fn discover_nodes_in(unit_dirs: &[&Path]) -> Vec<NodeCandidate> {
    let mut result = Vec::new();
    let mut names = HashSet::new();
    let mut budget = 1024;
    for dir in unit_dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.take(budget).flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".service") || !name.contains("node") || !names.insert(name.clone())
            {
                continue;
            }
            if let Some(candidate) = parse_unit(&entry.path(), &name) {
                result.push(candidate);
            }
        }
    }
    result
}
fn words(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escape = false;
    for c in s.chars() {
        if escape {
            word.push(c);
            escape = false;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escape = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
        } else if c == '\'' || c == '"' {
            quote = Some(c);
        } else if c.is_whitespace() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}
fn expand(s: &str, env: &HashMap<String, String>) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        let mut key = String::new();
        if it.peek() == Some(&'{') {
            it.next();
            for ch in it.by_ref() {
                if ch == '}' {
                    break;
                }
                key.push(ch);
            }
        } else {
            while it
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                key.push(it.next().unwrap());
            }
        }
        if let Some(v) = env.get(&key) {
            out.push_str(v);
        }
    }
    out
}
fn absolute(base: &Path, value: &str) -> PathBuf {
    let p = Path::new(value);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}
fn parse_unit(path: &Path, name: &str) -> Option<NodeCandidate> {
    let text = String::from_utf8(read_file(path, 256 * 1024).ok()?)
        .ok()?
        .replace("\\\n", " ");
    let mut env = HashMap::new();
    let mut environment_files = Vec::new();
    let mut working = None;
    let mut exec = None;
    let mut in_service = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_service = line == "[Service]";
            continue;
        }
        if !in_service || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "Environment" => {
                for assignment in words(value) {
                    if let Some((k, v)) = assignment.split_once('=') {
                        env.insert(k.to_owned(), v.to_owned());
                    }
                }
            }
            "EnvironmentFile" => environment_files.extend(words(value)),
            "WorkingDirectory" => working = Some(value.to_owned()),
            "ExecStart" => {
                if value.is_empty() {
                    exec = None;
                } else {
                    exec = Some(value.to_owned());
                }
            }
            _ => {}
        }
    }
    for file in environment_files {
        let file = expand(file.trim_start_matches('-'), &env);
        let Ok(bytes) = read_file(Path::new(&file), 256 * 1024) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
            if line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let v = words(v.trim()).join(" ");
                env.insert(k.trim().to_owned(), expand(&v, &env));
            }
        }
    }
    let work = working
        .map(|w| PathBuf::from(expand(w.trim_matches('"'), &env)))
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| PathBuf::from("/"));
    let args: Vec<String> = words(&exec?)
        .into_iter()
        .map(|s| expand(&s, &env))
        .collect();
    let executable = args.first()?.trim_start_matches(['-', '+', '!', ':', '@']);
    let executable = Path::new(executable).file_name()?.to_str()?;
    let is_node = |s: &str| {
        Path::new(s)
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s == "cardano-node" || s.starts_with("cnode"))
    };
    if !is_node(executable)
        && !(matches!(executable, "sh" | "bash") && args.get(1).is_some_and(|s| is_node(s)))
    {
        return None;
    }
    let config = args.iter().enumerate().find_map(|(i, a)| {
        if a == "--config" {
            args.get(i + 1).map(|s| absolute(&work, s))
        } else {
            a.strip_prefix("--config=").map(|s| absolute(&work, s))
        }
    });
    let json = config
        .as_ref()
        .and_then(|p| read_file(p, 1024 * 1024).ok())
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let config_dir = config.as_ref().and_then(|p| p.parent()).unwrap_or(&work);
    let mut dirs = vec![
        work.clone(),
        config_dir.to_path_buf(),
        work.join("files"),
        config_dir.join("files"),
    ];
    dirs.dedup();
    let find = |key: &str, suffix: &str| -> Option<PathBuf> {
        if let Some(value) = json.as_ref().and_then(|v| v[key].as_str()) {
            return Some(absolute(config_dir, value));
        }
        for dir in &dirs {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            let mut paths: Vec<_> = entries
                .take(1024)
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.ends_with(suffix))
                })
                .collect();
            paths.sort();
            if let Some(path) = paths
                .into_iter()
                .find(|p| read_file(p, 16 * 1024 * 1024).is_ok())
            {
                return Some(path);
            }
        }
        None
    };
    let byron = find("ByronGenesisFile", "byron-genesis.json")?;
    let shelley = find("ShelleyGenesisFile", "shelley-genesis.json")?;
    let bytes = read_file(&shelley, 16 * 1024 * 1024).ok()?;
    let magic = serde_json::from_slice::<Value>(&bytes)
        .ok()?
        .get("networkMagic")?
        .as_u64()?;
    let (network, byron_epochs) = match magic {
        764824073 => (KnownNetwork::Mainnet, Some(208)),
        1 => (KnownNetwork::Preprod, Some(4)),
        2 => (KnownNetwork::Preview, Some(0)),
        _ => (
            KnownNetwork::Custom(name.trim_end_matches(".service").to_owned()),
            None,
        ),
    };
    let shelley_hash_matches = json
        .as_ref()
        .and_then(|v| v["ShelleyGenesisHash"].as_str())
        .map(|expected| {
            format!("{:x}", Blake2b::<U32>::digest(&bytes)).eq_ignore_ascii_case(expected)
        });
    Some(NodeCandidate {
        unit: name.to_owned(),
        config,
        byron,
        shelley,
        network,
        byron_epochs,
        shelley_hash_matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unit_environment_config_fallback_and_hash() {
        let root = std::env::temp_dir().join(format!("p2-node-{}", std::process::id()));
        let units = root.join("units");
        let work = root.join("node");
        let files = work.join("files");
        fs::create_dir_all(&units).unwrap();
        fs::create_dir_all(&files).unwrap();
        fs::write(files.join("x-byron-genesis.json"), "{}").unwrap();
        let genesis = r#"{"networkMagic":1}"#;
        fs::write(files.join("x-shelley-genesis.json"), genesis).unwrap();
        let hash = format!("{:x}", Blake2b::<U32>::digest(genesis.as_bytes()));
        fs::write(work.join("config.json"), format!(r#"{{"ByronGenesisFile":"files/x-byron-genesis.json","ShelleyGenesisFile":"files/x-shelley-genesis.json","ShelleyGenesisHash":"{hash}"}}"#)).unwrap();
        fs::write(work.join("env"), "CONFIG=config.json\n").unwrap();
        fs::write(units.join("pprod-node.service"), format!("[Service]\nWorkingDirectory={}\nEnvironmentFile=-{}\nExecStart=/usr/bin/cardano-node run \\\n --config ${{CONFIG}}\n", work.display(), work.join("env").display())).unwrap();
        fs::write(units.join("other-node.service"), format!("[Service]\nWorkingDirectory={}\nEnvironment=\"CONFIG=config.json\"\nExecStart=/usr/bin/cardano-node run --config $CONFIG\n", work.display())).unwrap();
        fs::write(
            units.join("node-exporter.service"),
            "[Service]\nExecStart=/usr/bin/node_exporter\n",
        )
        .unwrap();
        fs::write(
            units.join("guild-node.service"),
            format!(
                "[Service]\nWorkingDirectory={}\nExecStart=/bin/bash cnode.sh\n",
                work.display()
            ),
        )
        .unwrap();
        fs::write(
            work.join("config.yaml"),
            "ByronGenesisFile: files/x-byron-genesis.json\n",
        )
        .unwrap();
        fs::write(units.join("yaml-node.service"), format!("[Service]\nWorkingDirectory={}\nExecStart=/usr/bin/cardano-node run --config config.yaml\n", work.display())).unwrap();
        let nodes = discover_nodes_in(&[&units]);
        assert_eq!(nodes.len(), 4);
        for node in &nodes {
            assert_eq!(node.network, KnownNetwork::Preprod);
            assert_eq!(node.byron_epochs, Some(4));
        }
        assert_eq!(
            nodes
                .iter()
                .find(|n| n.unit == "pprod-node.service")
                .unwrap()
                .shelley_hash_matches,
            Some(true)
        );
        for (magic, network, epochs) in [
            (764824073, KnownNetwork::Mainnet, 208),
            (2, KnownNetwork::Preview, 0),
        ] {
            fs::write(
                files.join("x-shelley-genesis.json"),
                format!(r#"{{"networkMagic":{magic}}}"#),
            )
            .unwrap();
            let nodes = discover_nodes_in(&[&units]);
            assert!(
                nodes
                    .iter()
                    .all(|n| n.network == network && n.byron_epochs == Some(epochs))
            );
        }
        fs::write(work.join("config.json"), r#"{"ByronGenesisFile":"files/x-byron-genesis.json","ShelleyGenesisFile":"files/x-shelley-genesis.json","ShelleyGenesisHash":"bad"}"#).unwrap();
        fs::write(
            files.join("x-shelley-genesis.json"),
            r#"{"networkMagic":42}"#,
        )
        .unwrap();
        let nodes = discover_nodes_in(&[&units]);
        assert_eq!(
            nodes
                .iter()
                .find(|n| n.unit == "pprod-node.service")
                .unwrap()
                .shelley_hash_matches,
            Some(false)
        );
        assert!(
            nodes
                .iter()
                .all(|n| n.byron_epochs.is_none() && matches!(n.network, KnownNetwork::Custom(_)))
        );
        fs::remove_dir_all(root).unwrap();
    }
}
