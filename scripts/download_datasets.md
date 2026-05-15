# Public Benchmark Dataset Setup

This project does not automatically download large public datasets. Download them manually from the official/source repositories, place the CSV files in the folders below, then run the preprocessing script.

## CICIDS2017

Official source: Canadian Institute for Cybersecurity, University of New Brunswick
https://www.unb.ca/cic/datasets/ids-2017.html

Place CSV flow files in:

```bash
datasets/public/CICIDS2017/
```

Preprocess:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/prepare_public_datasets.py --dataset CICIDS2017
```

Output:

```text
datasets/processed/security_train.csv
datasets/processed/security_test.csv
```

## CSE-CIC-IDS2018

Official description: Canadian Institute for Cybersecurity, University of New Brunswick
https://www.unb.ca/cic/datasets/ids-2018.html

AWS Open Data Registry entry:
https://registry.opendata.aws/cse-cic-ids2018/

Place processed CICFlowMeter CSV files in:

```bash
datasets/public/CSE_CIC_IDS2018/
```

Preprocess:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/prepare_public_datasets.py --dataset CSE_CIC_IDS2018
```

## UNSW-NB15

Official source: UNSW Canberra Cyber Range Lab
https://research.unsw.edu.au/projects/unsw-nb15-dataset

Place UNSW-NB15 CSV files in:

```bash
datasets/public/UNSW_NB15/
```

Preprocess:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/prepare_public_datasets.py --dataset UNSW_NB15
```

## MAWI Traffic Archive

Official source: MAWI Working Group Traffic Archive
https://mawi.wide.ad.jp/mawi/

MAWI is optional. The preprocessor expects a flow-like CSV. If you download PCAP traces, convert them to CSV/flow records first using your preferred flow tool, then place the CSV files in:

```bash
datasets/public/MAWI/
```

This project also includes a lightweight built-in converter for MAWI PCAP files:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/convert_mawi_pcap_to_flows.py \
  --pcap datasets/public/MAWI/202401011400.pcap/202401011400.pcap \
  --output datasets/public/MAWI/flows/202401011400_flows.csv \
  --max-packets 1000000
```

Use `--max-packets 0` for a full conversion if disk space and time allow.

Preprocess:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/prepare_public_datasets.py --dataset MAWI
```

## Training Commands

For the professional hybrid strategy, build a security dataset from all
available public CSVs plus live SDN security telemetry:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/prepare_hybrid_security_dataset.py --rows-per-file 12000 --live-limit 50000
```

Then train/evaluate:

```bash
source /home/patrick/sdn-env/bin/activate
python scripts/train_security_model.py
python scripts/train_congestion_model.py
python scripts/train_qos_model.py
python scripts/evaluate_models.py
```

Model outputs are written to:

```text
datasets/models/security_model.pkl
datasets/models/congestion_model.pkl
datasets/models/qos_model.pkl
datasets/models/training_report.json
```

Install ML dependencies first if they are not already installed:

```bash
pip install scikit-learn joblib numpy
```
