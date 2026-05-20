# Sequence Diagrams — End-to-End Data Flow

## 1. Full System Startup Sequence

```
User                    Flask App              PipelineController        DDoSPipeline          PredictionPipeline
 │                         │                         │                       │                       │
 │── POST /start ─────────▶│                         │                       │                       │
 │                         │── start_pipeline() ────▶│                       │                       │
 │                         │                         │── initialize_components()                     │
 │                         │                         │                       │                       │
 │                         │                         │── new DDoSPipeline() ──▶                       │
 │                         │                         │── new LocalPredictionPipeline() ──────────────▶│
 │                         │                         │── model_updater.start_periodic_update()       │
 │                         │                         │                       │                       │
 │                         │                         │── Thread: DDoSPipeline.run() ────────────────▶│
 │                         │                         │                       │── start()             │
 │                         │                         │                       │── PacketCapturer.start()
 │                         │                         │                       │   (sniff + rotation)  │
 │                         │                         │                       │── FileDispatcher.start()
 │                         │                         │                       │   (scan + dispatch)   │
 │                         │                         │                       │                       │
 │                         │                         │── Thread: Detection.start() ──────────────────▶│
 │                         │                         │                       │   ├── Discovery worker │
 │                         │                         │                       │   └── Processing worker│
 │                         │                         │                       │                       │
 │◀── 200 OK ──────────────│◀── {"status":"success"}─│                       │                       │
 │                         │                         │                       │                       │
```

## 2. Packet Capture → DDoS Detection → Mitigation Sequence

```
Network          PacketCapturer        FlowTracker        DRLMitigationAgent    MitigationAgent    iptables
  │                    │                    │                      │                    │              │
  │── Packet ─────────▶│                    │                      │                    │              │
  │                    │── extract metadata │                      │                    │              │
  │                    │  (IP, ports, proto)│                      │                    │              │
  │                    │                    │                      │                    │              │
  │                    │── update() ────────▶│                      │                    │              │
  │                    │                    │── Track flow stats    │                    │              │
  │                    │                    │── Compute IAT, flags  │                    │              │
  │                    │                    │── Check inference     │                    │              │
  │                    │                    │   trigger?            │                    │              │
  │                    │                    │                      │                    │              │
  │                    │                    │── (every 5 packets)   │                    │              │
  │                    │                    │── return flow_key ───▶│                    │              │
  │                    │                    │                      │                    │              │
  │                    │                    │                      │── get_features()   │              │
  │                    │                    │◀─────────────────────│                    │              │
  │                    │                    │── 81-dim vector ─────▶│                    │              │
  │                    │                    │                      │                    │              │
  │                    │                    │                      │── model.predict()  │              │
  │                    │                    │                      │  (PPO inference)   │              │
  │                    │                    │                      │                    │              │
  │                    │                    │                      │── action=1,        │              │
  │                    │                    │                      │   conf=0.92        │              │
  │                    │                    │                      │                    │              │
  │                    │                    │                      │── conf >= threshold?│              │
  │                    │                    │                      │── YES → block!     │              │
  │                    │                    │                      │                    │              │
  │                    │                    │                      │── _do_block(ip) ───────────────────▶│
  │                    │                    │                      │                    │── iptables -A  │
  │                    │                    │                      │                    │  DDOS_BLOCK   │
  │                    │                    │                      │                    │  -s ip -j DROP│
  │                    │                    │                      │                    │              │
  │                    │                    │                      │◀───────────────────│              │
  │                    │                    │                      │                    │              │
  │                    │── on_packet(ip) ────────────────────────────────────────────────▶│              │
  │                    │                    │                      │   (rate check)       │              │
  │                    │                    │                      │                    │              │
  │◀── DROP ──────────│                    │                      │                    │              │
  │  (future packets) │                    │                      │                    │              │
```

## 3. Batch Processing Pipeline (PCAP → CSV → Prediction)

```
Capture Dir        FileDispatcher     CICFeatureExtractor    PredictionPipeline    Controller        Alerting
    │                   │                     │                      │                  │                │
    │── .pcap file ────▶│                     │                      │                  │                │
    │  (settled 10s)    │                     │                      │                  │                │
    │                   │── move_to_in_progress()                    │                  │                │
    │                   │                     │                      │                  │                │
    │                   │── process_pcap() ──▶│                      │                  │                │
    │                   │                     │── rdpcap()           │                  │                │
    │                   │                     │── Extract flows      │                  │                │
    │                   │                     │── Compute 84 features│                  │                │
    │                   │                     │── Write CSV ────────▶│                  │                │
    │                   │                     │                      │                  │                │
    │                   │── move_to_processed()│                      │                  │                │
    │                   │  (delete .pcap)     │                      │                  │                │
    │                   │                     │                      │                  │                │
    │                   │                     │                      │── Discovery:     │                │
    │                   │                     │                      │   find CSV       │                │
    │                   │                     │                      │                  │                │
    │                   │                     │                      │── _process_file()│                │
    │                   │                     │                      │  ├── Read CSV    │                │
    │                   │                     │                      │  ├── Preprocess  │                │
    │                   │                     │                      │  ├── predict_batch()               │
    │                   │                     │                      │  ├── Save pred CSV                 │
    │                   │                     │                      │                  │                │
    │                   │                     │                      │── detection_callback() ──────────▶│
    │                   │                     │                      │   (for each row) │                │
    │                   │                     │                      │                  │                │
    │                   │                     │                      │                  │── record_detection()
    │                   │                     │                      │                  │  ├── Update counters
    │                   │                     │                      │                  │  ├── Mitigation check
    │                   │                     │                      │                  │  └── Alert if DDoS
    │                   │                     │                      │                  │                │
    │                   │                     │                      │                  │                │── send_alert()
    │                   │                     │                      │                  │                │  ├── Dashboard
    │                   │                     │                      │                  │                │  ├── Email
    │                   │                     │                      │                  │                │  └── Webhook
    │                   │                     │                      │                  │                │
    │                   │                     │                      │── Delete CSV     │                │
```

## 4. Model Update Sequence

```
Remote API       ModelUpdater        LocalPredictionPipeline    Disk
    │                 │                       │                  │
    │                 │── (every 2 hours)      │                  │
    │                 │── download_model() ───▶│                  │
    │◀── GET /api/...─│                       │                  │
    │── .pt file ─────▶│                       │                  │
    │                 │                       │                  │
    │                 │── validate_model()     │                  │
    │                 │  ├── load_model()      │                  │
    │                 │  ├── check policy attr │                  │
    │                 │  └── ✓ Valid           │                  │
    │                 │                       │                  │
    │                 │── backup current ────────────────────────▶│
    │                 │  (.bak.{timestamp})   │                  │
    │                 │                       │                  │
    │                 │── copy new model ────────────────────────▶│
    │                 │                       │                  │
    │                 │── with lock:           │                  │
    │                 │   load into memory     │                  │
    │                 │   self.model = new     │                  │
    │                 │───────────────────────▶│                  │
    │                 │                       │                  │
    │                 │── cleanup temp + backup──────────────────▶│
    │                 │                       │                  │
    │                 │── next discovery ─────▶│                  │
    │                 │                       │── use model_updater.model
    │                 │                       │  (hot-swapped!)  │
```

## 5. Alert Flow Sequence

```
Controller        AlertManager        DashboardChannel    EmailChannel    WebhookChannel
    │                  │                    │                  │                │
    │── DDoS detected  │                    │                  │                │
    │  (conf >= 0.8)   │                    │                  │                │
    │                  │                    │                  │                │
    │── send_alert() ──▶│                   │                  │                │
    │  (type, severity,│                    │                  │                │
    │   title, message)│                    │                  │                │
    │                  │── rate_limit check  │                  │                │
    │                  │── dedup check       │                  │                │
    │                  │                    │                  │                │
    │                  │── send() ──────────▶│                  │                │
    │                  │                    │── append to deque │                │
    │                  │                    │◀─────────────────│                │
    │                  │                    │                  │                │
    │                  │── send() ─────────────────────────────▶│                │
    │                  │                    │                  │── SMTP connect  │
    │                  │                    │                  │── send HTML email
    │                  │                    │                  │◀───────────────│
    │                  │                    │                  │                │
    │                  │── send() ──────────────────────────────────────────────▶│
    │                  │                    │                  │── POST webhook  │
    │                  │                    │                  │  (JSON payload) │
    │                  │                    │                  │◀───────────────│
    │                  │                    │                  │                │
    │                  │── save_history()   │                  │                │
    │                  │  (alert_history.json)                 │                │
    │                  │                    │                  │                │
    │◀── Alert object ─│                    │                  │                │
```

## 6. Shutdown Sequence

```
User              Flask App         PipelineController    DDoSPipeline    PredictionPipeline
  │                  │                    │                  │                  │
  │── POST /stop ───▶│                    │                  │                  │
  │                  │── stop_pipeline() ─▶│                  │                  │
  │                  │                    │                  │                  │
  │                  │                    │── pipeline.stop() ──────────────────▶│
  │                  │                    │                  │── shutdown_event.set()
  │                  │                    │                  │── capturer.stop() │
  │                  │                    │                  │  (sniffer join)  │
  │                  │                    │                  │── dispatcher.stop()
  │                  │                    │                  │  (dispatch join) │
  │                  │                    │                  │                  │
  │                  │                    │── detect.stop() ─────────────────────▶│
  │                  │                    │                  │  ├── stop_event.set()
  │                  │                    │                  │  ├── discovery join
  │                  │                    │                  │  └── worker join │
  │                  │                    │                  │                  │
  │                  │                    │── model_updater.stop()              │
  │                  │                    │── ebpf.shutdown()                   │
  │                  │                    │── drl.cleanup_expired()             │
  │                  │                    │                  │                  │
  │                  │                    │── join threads (5s timeout)         │
  │                  │                    │── clear references                  │
  │                  │                    │                  │                  │
  │◀── 200 OK ───────│◀── {"status":"success"}                                  │
```
