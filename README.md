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

---

## 📂 Repository Structure

```
├── dataset/
│   Analysis data (Extracted Features)
│
├── result graphs/
│   Generated graphs and visualizations
│
├── compare (7).ipynb
│   Google Colab Notebook for comparison and analysis
│
├── parse_json.py
│   Parses Android JSON reports
│
├── parse_ios_json.py
│   Parses iOS JSON reports
│
├── save_json.py
│   Save MobSF results as json
│
├── save_scorecard.py
│   Save MobSF Scorecard
│
├── reviews.py
│   User perception analysis of google play store reviews
│
├── Research Paper.pdf
│   Final research paper
│
├── README.md
│   Project documentation
```
