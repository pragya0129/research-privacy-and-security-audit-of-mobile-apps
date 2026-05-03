# 📱 Privacy & Security Audit of Mobile Applications

This repository contains the implementation, datasets, analysis scripts, and results for the research paper:

**“Identification and Comparative Analysis of Privacy & Security Risks in Android and iOS Applications”**

---

## 📌 Overview

With the increasing reliance on mobile applications, user privacy and data security have become critical concerns. This project performs a **comparative security analysis of Android and iOS applications** using static analysis techniques.

The study focuses on:

- Permissions usage  
- Tracking libraries  
- WebView behavior  
- Cryptographic practices  
- Network security configurations  
- Platform-specific privacy risks  

---

## 🧠 Methodology

- Tools Used: **MobSF (Mobile Security Framework)**  
- Platforms Compared: **Android vs iOS**  
- Data Source: Extracted JSON reports from analyzed applications  
- Processing: Custom Python scripts to parse, extract, and standardize features  
- Output: Structured scorecards and visual comparison graphs  

---

## 📂 Repository Structure
├── dataset/ # Raw analysis data (MobSF outputs / JSON files)
├── result graphs/ # Generated graphs and visualizations
│
├── compare (7).ipynb # Jupyter Notebook for comparison and analysis
│
├── parse_json.py # Parses Android JSON reports
├── parse_ios_json.py # Parses iOS JSON reports
├── save_json.py # Utility to clean/store processed data
├── save_scorecard.py # Generates standardized security scorecards
├── reviews.py # Analysis of extracted features / metrics
│
├── Research Paper.pdf # Final research paper
├── README.md # Project documentation

