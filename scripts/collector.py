import time
import pandas as pd
from pathlib import Path
from datetime import datetime
from parser import parse_conn_log
from features import extract_features

# ─── المسارات ────────────────────────────────────────────────────────────────
CONN_LOG   = "/opt/zeek/logs/current/conn.log"
OUTPUT_DIR = Path("/home/mtech/zeek-ids/data/processed")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ─── Noise Filter (نفس window_engine.py) ─────────────────────────────────────
NOISE_DST_IPS = {
    "224.0.0.251", "224.0.0.1",
    "192.168.68.255", "192.168.1.255", "255.255.255.255",
    "ff02::fb", "ff02::1:3", "ff02::1", "ff02::2", "ff02::16",
}
NOISE_PORTS = {137, 138, 139, 5353, 1900, 5355}

def filter_noise(df: pd.DataFrame) -> pd.DataFrame:
    """إزالة broadcast/multicast — ليست اتصالات حقيقية"""
    if df.empty:
        return df
    if "dst_ip" in df.columns:
        df = df[~df["dst_ip"].isin(NOISE_DST_IPS)]
    if "dst_port" in df.columns:
        df = df[~df["dst_port"].isin(NOISE_PORTS)]
    return df

# ─── ملف البيانات اليومي ─────────────────────────────────────────────────────
def get_output_file():
    today = datetime.now().strftime("%Y-%m-%d")
    return OUTPUT_DIR / f"baseline_{today}.csv"

# ─── State ───────────────────────────────────────────────────────────────────
STATE_FILE = Path("/home/mtech/zeek-ids/logs/collector_state.json")

def load_state():
    """
    يقرأ آخر ts معالج من مصدرين:
    1. state.json (سريع)
    2. CSV اليوم (أكثر موثوقية — يمنع التكرار بعد إعادة التشغيل)
    يأخذ الأعلى منهما
    """
    import json

    state_ts = 0
    if STATE_FILE.exists():
        with open(STATE_FILE) as f:
            s = json.load(f)
            state_ts = s.get("last_processed", 0)

    # تحقق من الـ CSV اليومي
    csv_ts = 0
    output_file = get_output_file()
    if output_file.exists():
        try:
            df_existing = pd.read_csv(output_file, usecols=["ts"])
            if not df_existing.empty:
                csv_ts = float(df_existing["ts"].max())
        except Exception:
            pass

    last_ts = max(state_ts, csv_ts)
    if csv_ts > state_ts:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] "
              f"🔄 مزامنة من CSV: last_ts={csv_ts:.0f}")

    return last_ts, 0

def save_state(last_processed, last_log_size):
    import json
    with open(STATE_FILE, "w") as f:
        json.dump({
            "last_processed": last_processed,
            "last_log_size":  last_log_size
        }, f)

last_processed, last_log_size = load_state()

# ─── الحلقة الرئيسية ─────────────────────────────────────────────────────────
def collect():
    global last_processed, last_log_size

    df = parse_conn_log(CONN_LOG)
    if df.empty:
        return

    # كشف إعادة تشغيل Zeek
    current_size = len(df)
    if current_size < last_log_size:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔄 Zeek أعاد التشغيل — إعادة ضبط المؤشر")
        last_processed = 0
    last_log_size = current_size

    # السجلات الجديدة فقط
    new_df = df[df["ts"] > last_processed]
    if new_df.empty:
        return

    # استخراج الـ features
    features = extract_features(new_df)

    # ✅ فلتر الـ noise قبل الحفظ
    before     = len(features)
    features   = filter_noise(features).reset_index(drop=True)
    noise_removed = before - len(features)

    if features.empty:
        last_processed = df["ts"].max()
        save_state(last_processed, last_log_size)
        return
    features = features.drop_duplicates().reset_index(drop=True)
    # حفظ في CSV يومي
    output_file = get_output_file()
    features.to_csv(
        output_file,
        mode="a",
        header=not output_file.exists(),
        index=False
    )

    # تحديث الـ state
    last_processed = df["ts"].max()
    save_state(last_processed, last_log_size)

    # عداد السطور
    total = sum(1 for _ in open(output_file))

    noise_info = f" | 🔇 noise: {noise_removed}" if noise_removed > 0 else ""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] "
          f"✅ حفظ {len(features)} سجل جديد | "
          f"المجموع: {total} سطر{noise_info}")


if __name__ == "__main__":
    print("🚀 بدأ جمع البيانات...")
    print(f"📁 الحفظ في: {get_output_file()}")
    print("اضغط Ctrl+C للإيقاف\n")

    while True:
        try:
            collect()
            time.sleep(30)
        except KeyboardInterrupt:
            print("\n⛔ تم الإيقاف")
            break
        except Exception as e:
            print(f"❌ خطأ: {e}")
            time.sleep(30)
