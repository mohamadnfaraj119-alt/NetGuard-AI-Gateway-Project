import pandas as pd
import numpy as np
from datetime import datetime

DNS_FIELDS = [
    "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "trans_id", "rtt", "query", "qclass", "qclass_name",
    "qtype", "qtype_name", "rcode", "rcode_name", "AA", "TC",
    "RD", "RA", "Z", "answers", "TTLs", "rejected"
]

SSL_FIELDS = [
    "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
    "version", "cipher", "curve", "server_name", "resumed",
    "last_alert", "next_protocol", "established", "ssl_history",
    "cert_chain_fps", "client_cert_chain_fps", "subject",
    "issuer", "client_subject", "client_issuer", "sni_matches_cert",
    "validation_status"
]

def parse_dns_log(filepath="/opt/zeek/logs/current/dns.log"):
    rows = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                values = line.strip().split("\t")
                if len(values) != len(DNS_FIELDS):
                    continue
                rows.append(dict(zip(DNS_FIELDS, values)))
        df = pd.DataFrame(rows)
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        df.replace("-", None, inplace=True)
        return df
    except Exception as e:
        return pd.DataFrame()

def parse_ssl_log(filepath="/opt/zeek/logs/current/ssl.log"):
    rows = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                values = line.strip().split("\t")
                if len(values) < 14:
                    continue
                row = {}
                for i, field in enumerate(SSL_FIELDS):
                    row[field] = values[i] if i < len(values) else None
                rows.append(row)
        df = pd.DataFrame(rows)
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
        df.replace("-", None, inplace=True)
        return df
    except Exception as e:
        return pd.DataFrame()

def extract_conn_features(df):
    features = pd.DataFrame()
    features["duration"]      = df["duration"].fillna(0)
    features["orig_bytes"]    = df["orig_bytes"].fillna(0)
    features["resp_bytes"]    = df["resp_bytes"].fillna(0)
    features["orig_pkts"]     = df["orig_pkts"].fillna(0)
    features["resp_pkts"]     = df["resp_pkts"].fillna(0)
    features["orig_ip_bytes"] = df["orig_ip_bytes"].fillna(0)
    features["resp_ip_bytes"] = df["resp_ip_bytes"].fillna(0)
    features["missed_bytes"]  = df["missed_bytes"].fillna(0)
    features["bytes_ratio"]       = df["resp_bytes"] / (df["orig_bytes"] + 1)
    features["pkts_ratio"]        = df["resp_pkts"]  / (df["orig_pkts"]  + 1)
    features["avg_orig_pkt_size"] = df["orig_bytes"] / (df["orig_pkts"]  + 1)
    features["avg_resp_pkt_size"] = df["resp_bytes"] / (df["resp_pkts"]  + 1)
    features["proto_tcp"]  = (df["proto"] == "tcp").astype(int)
    features["proto_udp"]  = (df["proto"] == "udp").astype(int)
    features["proto_icmp"] = (df["proto"] == "icmp").astype(int)
    features["conn_state_S0"]  = (df["conn_state"] == "S0").astype(int)
    features["conn_state_SF"]  = (df["conn_state"] == "SF").astype(int)
    features["conn_state_REJ"] = (df["conn_state"] == "REJ").astype(int)
    features["conn_state_OTH"] = (df["conn_state"] == "OTH").astype(int)
    features["dst_port"]           = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0)
    features["is_well_known_port"] = (features["dst_port"] < 1024).astype(int)
    features["is_http"]            = (features["dst_port"] == 80).astype(int)
    features["is_https"]           = (features["dst_port"] == 443).astype(int)
    features["is_dns"]             = (features["dst_port"] == 53).astype(int)
    features["is_ssh"]             = (features["dst_port"] == 22).astype(int)
    features["is_external"] = (~df["dst_ip"].str.startswith("192.168.")).astype(int)
    features["hour_of_day"] = pd.to_datetime(df["ts"], unit="s").dt.hour
    features["day_of_week"] = pd.to_datetime(df["ts"], unit="s").dt.dayofweek
    features["is_night"]    = ((features["hour_of_day"] >= 0) & (features["hour_of_day"] < 6)).astype(int)
    features["src_ip"] = df["src_ip"]
    features["dst_ip"] = df["dst_ip"]
    features["ts"]     = df["ts"]
    return features

def extract_dns_features(dns_df):
    if dns_df.empty:
        return pd.DataFrame()
    features = pd.DataFrame()
    features["ts"]                  = dns_df["ts"]
    features["src_ip"]              = dns_df["src_ip"]
    features["dns_qtype_A"]         = (dns_df["qtype_name"] == "A").astype(int)
    features["dns_qtype_AAAA"]      = (dns_df["qtype_name"] == "AAAA").astype(int)
    features["dns_qtype_MX"]        = (dns_df["qtype_name"] == "MX").astype(int)
    features["dns_qtype_TXT"]       = (dns_df["qtype_name"] == "TXT").astype(int)
    features["dns_success"]         = (dns_df["rcode_name"] == "NOERROR").astype(int)
    features["dns_rejected"]        = (dns_df["rejected"] == "T").astype(int)
    features["dns_query_len"]       = dns_df["query"].fillna("").apply(len)
    features["dns_subdomain_count"] = dns_df["query"].fillna("").apply(lambda x: x.count("."))
    features["dns_rtt"]             = pd.to_numeric(dns_df["rtt"], errors="coerce").fillna(0)
    return features

def extract_ssl_features(ssl_df):
    if ssl_df.empty:
        return pd.DataFrame()
    features = pd.DataFrame()
    features["ts"]                = ssl_df["ts"]
    features["src_ip"]            = ssl_df["src_ip"]
    features["dst_ip"]            = ssl_df["dst_ip"]
    features["ssl_version_TLS13"] = (ssl_df["version"] == "TLSv13").astype(int)
    features["ssl_version_TLS12"] = (ssl_df["version"] == "TLSv12").astype(int)
    features["ssl_version_old"]   = (~ssl_df["version"].isin(["TLSv13", "TLSv12", None])).astype(int)
    features["ssl_established"]   = (ssl_df["established"] == "T").astype(int)
    features["ssl_resumed"]       = (ssl_df["resumed"] == "T").astype(int)
    features["ssl_sni_match"]     = (ssl_df["sni_matches_cert"] == "T").astype(int)
    features["ssl_valid"]         = (ssl_df["validation_status"] == "ok").astype(int)
    features["ssl_sni_len"]       = ssl_df["server_name"].fillna("").apply(len)
    return features

def extract_features(df):
    return extract_conn_features(df)

if __name__ == "__main__":
    from parser import parse_conn_log
    print("=" * 50)
    print("🔍 اختبار conn.log")
    df = parse_conn_log()
    conn_features = extract_conn_features(df)
    print(f"✅ conn: {len(conn_features.columns)} ميزة | {len(conn_features)} سجل")
    print("\n🔍 اختبار dns.log")
    dns_df = parse_dns_log()
    if not dns_df.empty:
        dns_features = extract_dns_features(dns_df)
        print(f"✅ dns: {len(dns_features.columns)} ميزة | {len(dns_features)} سجل")
    else:
        print("⚠️  dns.log فارغ أو غير موجود")
    print("\n🔍 اختبار ssl.log")
    ssl_df = parse_ssl_log()
    if not ssl_df.empty:
        ssl_features = extract_ssl_features(ssl_df)
        print(f"✅ ssl: {len(ssl_features.columns)} ميزة | {len(ssl_features)} سجل")
    else:
        print("⚠️  ssl.log فارغ أو غير موجود")
    print("\n" + "=" * 50)
    print(f"📊 إجمالي ميزات conn: {len(conn_features.columns)}")
    print("=" * 50)
