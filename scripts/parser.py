import pandas as pd
from pathlib import Path

CONN_LOG = "/opt/zeek/logs/current/conn.log"

FIELDS = [
    "ts", "uid", "src_ip", "src_port", "dst_ip", "dst_port",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes",
    "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
    "resp_ip_bytes", "tunnel_parents", "ip_proto"
]

def parse_conn_log(filepath=CONN_LOG):
    rows = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                # تخطي الأسطر التعريفية
                if line.startswith("#"):
                    continue
                values = line.strip().split("\t")
                if len(values) != len(FIELDS):
                    continue
                rows.append(dict(zip(FIELDS, values)))

        df = pd.DataFrame(rows)

        # تحويل الأنواع
        numeric = [
            "ts", "duration", "orig_bytes", "resp_bytes",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
            "missed_bytes"
        ]
        for col in numeric:
            df[col] = pd.to_numeric(df[col], errors="coerce")

        # استبدال القيم الفارغة
        df.replace("-", None, inplace=True)

        print(f"✅ تم قراءة {len(df)} سجل من conn.log")
        return df

    except Exception as e:
        print(f"❌ خطأ: {e}")
        return pd.DataFrame()

if __name__ == "__main__":
    df = parse_conn_log()
    print(df[["src_ip", "dst_ip", "proto", "duration", "orig_bytes", "resp_bytes"]].head(10))
