use std::io::{BufRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Debug, Clone, serde::Serialize)]
pub struct TrafficSample {
    pub timestamp: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

pub struct TrafficLog {
    csv_path: PathBuf,
    samples: Arc<RwLock<Vec<TrafficSample>>>,
    pub tx_offset: u64,
    pub rx_offset: u64,
}

impl TrafficLog {
    /// Load existing CSV or create a new TrafficLog.
    /// Offset = last row's cumulative values so that atomic counters (starting at 0)
    /// can be added to produce the true cumulative total.
    pub fn load(path: &Path) -> Self {
        let mut samples = Vec::new();
        let mut tx_offset: u64 = 0;
        let mut rx_offset: u64 = 0;

        if path.exists() {
            if let Ok(file) = std::fs::File::open(path) {
                let reader = std::io::BufReader::new(file);
                for line in reader.lines() {
                    let line = match line {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let parts: Vec<&str> = line.split(',').collect();
                    if parts.len() >= 3 {
                        let ts = parts[0].parse::<i64>().unwrap_or(0);
                        let tx = parts[1].parse::<u64>().unwrap_or(0);
                        let rx = parts[2].parse::<u64>().unwrap_or(0);
                        if ts > 0 {
                            samples.push(TrafficSample {
                                timestamp: ts,
                                tx_bytes: tx,
                                rx_bytes: rx,
                            });
                        }
                    }
                }
            }
            if let Some(last) = samples.last() {
                tx_offset = last.tx_bytes;
                rx_offset = last.rx_bytes;
            }
            info!(
                "Loaded {} traffic samples from {:?}, offset tx={} rx={}",
                samples.len(),
                path,
                tx_offset,
                rx_offset
            );
        }

        TrafficLog {
            csv_path: path.to_path_buf(),
            samples: Arc::new(RwLock::new(samples)),
            tx_offset,
            rx_offset,
        }
    }

    /// Record a new sample: append to CSV file and in-memory vec.
    pub async fn record(&self, ts: i64, tx: u64, rx: u64) {
        let sample = TrafficSample {
            timestamp: ts,
            tx_bytes: tx,
            rx_bytes: rx,
        };

        // Append to CSV
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.csv_path)
        {
            let _ = writeln!(file, "{},{},{}", ts, tx, rx);
        } else {
            error!("Failed to open traffic CSV for writing: {:?}", self.csv_path);
        }

        self.samples.write().await.push(sample);
    }

    /// Query samples within a time range [start, end] (inclusive).
    pub async fn query_range(&self, start: i64, end: i64) -> Vec<TrafficSample> {
        let samples = self.samples.read().await;
        // Binary search for start index
        let lo = samples.partition_point(|s| s.timestamp < start);
        let hi = samples.partition_point(|s| s.timestamp <= end);
        samples[lo..hi].to_vec()
    }

    /// Query samples from the last `duration_secs` seconds.
    pub async fn query_last(&self, duration_secs: i64) -> Vec<TrafficSample> {
        let now = chrono::Utc::now().timestamp();
        self.query_range(now - duration_secs, now).await
    }

    /// Return adjusted cumulative TX bytes: offset + atomic counter value.
    pub fn adjusted_tx(&self, atomic_val: u64) -> u64 {
        self.tx_offset + atomic_val
    }

    /// Return adjusted cumulative RX bytes: offset + atomic counter value.
    pub fn adjusted_rx(&self, atomic_val: u64) -> u64 {
        self.rx_offset + atomic_val
    }

    /// Get distinct dates (YYYY-MM-DD) that have data.
    pub async fn dates_with_data(&self) -> Vec<String> {
        use std::collections::BTreeSet;
        let samples = self.samples.read().await;
        let mut dates = BTreeSet::new();
        for s in samples.iter() {
            if let Some(dt) = chrono::DateTime::from_timestamp(s.timestamp, 0) {
                dates.insert(dt.format("%Y-%m-%d").to_string());
            }
        }
        dates.into_iter().collect()
    }
}

/// Spawn a background task that records traffic samples every 60 seconds.
pub fn spawn_traffic_recorder(
    traffic_log: Arc<TrafficLog>,
    total_tx_bytes: Arc<AtomicU64>,
    total_rx_bytes: Arc<AtomicU64>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        // Skip the first immediate tick
        interval.tick().await;
        loop {
            interval.tick().await;
            let ts = chrono::Utc::now().timestamp();
            let tx = traffic_log.adjusted_tx(total_tx_bytes.load(Ordering::Relaxed));
            let rx = traffic_log.adjusted_rx(total_rx_bytes.load(Ordering::Relaxed));
            traffic_log.record(ts, tx, rx).await;
        }
    });
}
