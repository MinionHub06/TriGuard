# TriGuard 🛡️
### Explainable ML Framework for Real-Time SQL Injection Detection

![Python](https://img.shields.io/badge/Python-3.12-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask)
![XGBoost](https://img.shields.io/badge/XGBoost-1.7-orange?style=flat-square)
![AWS EC2](https://img.shields.io/badge/AWS-EC2-FF9900?style=flat-square&logo=amazonaws)
![License](https://img.shields.io/badge/License-MIT-purple?style=flat-square)

---

## Overview

**TriGuard** is a production-deployed SQL injection detection system combining XGBoost classification, SHAP explainability, and AWS cloud alerting via SNS and CloudWatch — exposed as a Flask REST API.

> 99.56% accuracy · 99.80% precision · sub-50ms inference latency

---

## Features

- 🤖 **XGBoost** trained on 25 hand-crafted syntactic, structural & behavioral features
- 🔍 **SHAP** per-prediction feature attribution returned with every API call
- 🔴 **Three risk levels** — High (block) · Medium (flag) · Low (allow)
- ☁️ **Amazon SNS** email alerts on high-risk detections
- 📋 **CloudWatch Logs** for full audit trail
- 📊 **Live dashboard** at `/dashboard`

---

## Model Performance

| Classifier       | Accuracy | Precision | Recall | F1-Score |
|------------------|----------|-----------|--------|----------|
| **XGBoost**      | **99.56%** | **99.80%** | **99.30%** | **99.55%** |
| Random Forest    | 98.12%   | 97.90%    | 98.40% | 98.14%   |
| SVM (RBF)        | 96.45%   | 96.10%    | 96.70% | 96.39%   |
| Logistic Reg.    | 93.20%   | 92.80%    | 93.50% | 93.14%   |
| Decision Tree    | 95.80%   | 95.20%    | 96.30% | 95.74%   |

---

## Tech Stack

| Layer      | Technology                      |
|------------|---------------------------------|
| ML Engine  | XGBoost 1.7, SHAP 0.41          |
| API Server | Flask 3.0, Python 3.12          |
| Compute    | AWS EC2 t2.micro · Ubuntu 22.04 |
| Alerting   | Amazon SNS                      |
| Monitoring | Amazon CloudWatch               |
| Database   | SQLite 3                        |

---

## Getting Started

| Endpoint     | Description                  |
|--------------|------------------------------|
| `/predict`   | Run detection on a SQL query |
| `/dashboard` | Live monitoring dashboard    |
| `/history`   | Prediction log               |
| `/health`    | API health check             |

---
