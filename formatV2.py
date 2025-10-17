import pandas as pd
import os
import re
import math

all_pq_kems = ("frodo640shake", "frodo976shake", "frodo1344shake",
               "bikel1", "bikel3", "bikel5",
               "mlkem512", "mlkem768", "mlkem1024",
               "hqc128", "hqc192", "hqc256")
all_cl_kems = ("x25519", "x448", "secp256_r1", "secp384_r1", "secp521_r1")
all_hybrid_kems= ("p256_frodo640shake" ,"x25519_frodo640shake" ,"x448_frodo640shake" ,"p384_frodo976shake" ,"x25519_frodo976shake" ,"x448_frodo976shake" ,"p521_frodo1344shake" ,"x25519_frodo1344shake" ,"x448_frodo1344shake" ,"p256_mlkem512" ,"x25519_mlkem512" ,"x448_mlkem512" ,"p384_mlkem768" ,"x25519_mlkem768" ,"x448_mlkem768" ,"p521_mlkem1024" ,"x25519_mlkem1024" ,"x448_mlkem1024" ,"p256_bikel1" ,"x25519_bikel1" ,"x448_bikel1" ,"p384_bikel3" ,"x25519_bikel3" ,"x448_bikel3" ,"p521_bikel5" ,"x25519_bikel5" ,"x448_bikel5" ,"p256_hqc128" ,"x25519_hqc128" ,"x448_hqc128" ,"p384_hqc192" ,"x25519_hqc192" ,"x448_hqc192" ,"p521_hqc256" ,"x25519_hqc256" ,"x448_hqc256")

all_sigs=(
    "p256_mldsa44",
    "rsa3072_mldsa44",
    "p256_falcon512",
    "rsa3072_falcon512",
    "p256_sphincsshake128fsimple",
    "rsa3072_sphincsshake128fsimple",
    "p256_mayo1",
    "rsa3072_mayo1",
    "p256_OV_Is",
    "rsa3072_OV_Is",
    "p256_snova2454shake",
    "rsa3072_snova2454shake")
all_kems=(
    "p256_frodo640shake",
    "x25519_frodo640shake",
    "x448_frodo640shake",
    "p384_frodo976shake",
    "p256_mlkem512",
    "x25519_mlkem512",
    "x448_mlkem512",
    "p256_bikel1",
    "x25519_bikel1",
    "x448_bikel1",
    "p256_hqc128",
    "x25519_hqc128",
    "x448_hqc128"
)


# all_sigs unused in rest of script; keep if needed
#all_sigs = ("rsa", "ed25519", "ed448", "prime256v1", "secp384r1", "secp521r1")

path = r"C:\Users\robso\Desktop\openssl test\results"

# We'll accumulate rows in lists of dicts, then build DataFrames once.
packets_rows = []
client_rows = []
client_perf_rows = []
server_rows = []

def find_in_tuple(s, choices):
    return next((x for x in choices if x in s), None)

folders = os.listdir(path)
for folder in folders:
    # infer metadata from folder name
    #broken
    #sig = folder.split("_")[0]
    sig=find_in_tuple(folder, all_sigs)
    if sig is None:
        # print(folder)
        continue#this is to skip the "sphincsshake128fsimple" only we accidentally added
    sig=sig.split("_")
    pq_sig="_".join(sig[1:])#test and add to entry
    cl_sig=sig[0]

    hybrid= find_in_tuple(folder, all_kems)
    hybrid=hybrid.split("_")
    pq = hybrid[1]
    cl = hybrid[0]

    # best-effort: if not found, set to None or skip
    if pq is None or cl is None:
        # print(folder)
        # skip folders that don't match expected naming pattern
        continue

    m = re.search(r"delay(\d+)", folder)
    delay = m.group(1) if m else ""
    m = re.search(r"loss(\d+)", folder)
    loss = m.group(1) if m else ""
    m = re.search(r"mtu(\d+)", folder)
    mtu = m.group(1) if m else ""

    folder_path = os.path.join(path, folder)
    file_paths = os.listdir(folder_path)
    for fname in file_paths:
        file_path = os.path.join(folder_path, fname)

        # s_client_packets.log
        if 's_client_packets.log' in fname:
            entry = {
                'cl_sig':cl_sig, 'pq_sig':pq_sig,
                'pq': pq, 'cl': cl,
                'delay': delay, 'loss': loss, 'mtu': mtu
            }
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = re.search(r":\s*([0-9]+)", line)
                    if m:
                        entry['packets'] = m.group(1)
                    break
            packets_rows.append(entry)

        # s_client.log
        if 's_client.log' in fname:
            entry = None
            current_idx = None
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m_idx = re.search(r"\[([0-9]{4})\]", line)
                    if m_idx:
                        idx = int(m_idx.group(1))
                        if current_idx is None:
                            # first index
                            current_idx = idx
                            entry = {
                                'cl_sig':cl_sig, 'pq_sig':pq_sig,
                                'pq': pq, 'cl': cl,
                                'delay': delay, 'loss': loss, 'mtu': mtu,
                                'idx': current_idx
                            }
                        elif idx != current_idx:
                            # push previous and start a new one
                            client_rows.append(entry)
                            current_idx = idx
                            entry = {
                                'cl_sig':cl_sig, 'pq_sig':pq_sig,
                                'pq': pq, 'cl': cl, 
                                'delay': delay, 'loss': loss, 'mtu': mtu,
                                'idx': current_idx
                            }
                        continue

                    # same index: look for fields
                    if "dec classical" in line:
                        m2 = re.search(r"([0-9]+)ns", line)
                        if m2:
                            entry['decap_cl'] = int(m2.group(1))
                    elif "dec pq" in line:
                        m2 = re.search(r"([0-9]+)ns", line)
                        if m2:
                            entry['decap_pq'] = int(m2.group(1))
                    elif "dec hybrid" in line:
                        m2 = re.search(r"([0-9]+)ns", line)
                        if m2:
                            entry['decap_hybrid'] = int(m2.group(1))
                    elif "sigtotal" in line:
                        m2 = re.search(r"sigtotal:\s*([0-9]+)ns", line)
                        if m2:
                            entry['sig_verify'] = int(m2.group(1))
                # end file: push last entry if exists
                if entry is not None:
                    client_rows.append(entry)

        # s_client_perf.log
        if 's_client_perf.log' in fname:
            entry = None
            current_idx = None
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m_idx = re.search(r"\[([0-9]{4})\]", line)
                    if not m_idx:
                        continue  # in this log, every line has an index, so safe
                    idx = int(m_idx.group(1))

                    if current_idx is None:
                        # first index
                        current_idx = idx
                        entry = {
                            'cl_sig':cl_sig, 'pq_sig':pq_sig,
                            'pq': pq, 'cl': cl,
                            'delay': delay, 'loss': loss, 'mtu': mtu,
                            'idx': current_idx
                        }
                    elif idx != current_idx:
                        # new index: flush previous
                        client_perf_rows.append(entry)
                        current_idx = idx
                        entry = {
                            'cl_sig':cl_sig, 'pq_sig':pq_sig,
                            'pq': pq, 'cl': cl, 
                            'delay': delay, 'loss': loss, 'mtu': mtu,
                            'idx': current_idx
                        }

                    # populate metrics for this line
                    if "User time" in line:
                        m2 = re.search(r"([0-9]*\.[0-9]{2})", line)
                        if m2:
                            entry['user_time'] = f'"{m2.group(1)}"'
                    elif "System time" in line:
                        m2 = re.search(r"([0-9]*\.[0-9]{2})", line)
                        if m2:
                            entry['system_time'] = f'"{m2.group(1)}"'
                    elif "Percent of CPU" in line:
                        m2 = re.search(r"([0-9]{1,3})%", line)
                        if m2:
                            entry['cpu'] = m2.group(1)
                    elif "Elapsed" in line:
                        m2 = re.search(r"([0-9]{1,2}:[0-9]{2}\.[0-9]{1,2})", line)
                        if m2:
                            entry['wall_clock_time'] = f'"{m2.group(1)}"'
                    elif "Maximum resident" in line:
                        m2 = re.search(r"kbytes\):\s*([0-9]+)", line)
                        if m2:
                            entry['memory'] = m2.group(1)
                    elif "WALL_TIME_S=" in line:
                        m2 = re.search(r"WALL_TIME_S=*([0-9]+)", line)
                        if m2:
                            entry['handshake_ns'] = m2.group(1)

                # flush last entry
                if entry is not None:
                    client_perf_rows.append(entry)

        # s_server.log
        if 's_server.log' in fname:
            entry = None
            current_idx = None
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    m = re.search(r"\[([0-9]{4})\]", line)
                    if not m:
                        continue
                    raw_idx = int(m.group(1))
                    idx = math.ceil(raw_idx / 3)
                    if current_idx is None:
                        current_idx = idx
                        entry = {
                            'cl_sig':cl_sig, 'pq_sig':pq_sig,
                            'pq': pq, 'cl': cl,
                            'delay': delay, 'loss': loss, 'mtu': mtu,
                            'idx': current_idx
                        }

                    if idx != current_idx:
                        server_rows.append(entry)
                        current_idx = idx
                        entry = {
                            'cl_sig':cl_sig, 'pq_sig':pq_sig,
                            'pq': pq, 'cl': cl,
                            'delay': delay, 'loss': loss, 'mtu': mtu,
                            'idx': current_idx
                        }

                    if "enc classical" in line:
                        m2 = re.search(r"([0-9]+)ns", line)
                        if m2:
                            entry['encap_cl'] = int(m2.group(1))
                    if "enc pq" in line:
                        m2 = re.search(r"([0-9]+)ns", line)
                        if m2:
                            entry['encap_pq'] = int(m2.group(1))
                    if "enc hybrid" in line:
                        m2 = re.search(r"([0-9]+)ns", line)
                        if m2:
                            entry['encap_hybrid'] = int(m2.group(1))
                if entry is not None:
                    server_rows.append(entry)

# Build DataFrames
s_client_packets_df = pd.DataFrame(packets_rows, columns=['cl_sig','pq_sig','cl','pq','delay','loss','mtu','packets'])
s_client_df = pd.DataFrame(client_rows, columns=['cl_sig','pq_sig','cl','pq','delay','loss','mtu','idx','decap_cl','decap_pq','decap_hybrid','sig_verify'])
s_client_perf_df = pd.DataFrame(client_perf_rows, columns=['cl_sig','pq_sig','cl','pq','delay','loss','mtu','idx','user_time','system_time','cpu','wall_clock_time','memory','handshake_ns'])
s_server_df = pd.DataFrame(server_rows, columns=['cl_sig','pq_sig','cl','pq','delay','loss','mtu','idx','encap_cl','encap_pq','encap_hybrid'])


merge_keys = ['cl_sig','pq_sig','cl','pq','delay','loss','mtu','idx']
merged_df = pd.merge(
    s_client_df,
    s_client_perf_df,
    on=merge_keys,
    how='inner'   # only keep rows that exist in both
)
merged_df = pd.merge(
    merged_df,
    s_server_df,
    on=merge_keys,
    how='inner'   # again only keep rows present in all three
)
merged_df = pd.merge(
    merged_df,
    s_client_packets_df,
    on=['cl_sig','pq_sig','cl','pq','delay','loss','mtu'],
    how='inner'   # again only keep rows present in all three
)
merged_df.reset_index(drop=True, inplace=True)
merged_df.to_csv('./all.csv', index=False)
# Save CSVs
# s_client_packets_df.to_csv('./packet.csv', index=False)
# merged_df_temp.to_csv('./merged.csv', index=False)

# s_client_df.to_csv('./s_client_df.csv', index=False)
# s_client_perf_df.to_csv('./s_client_perf_df.csv', index=False)
# s_server_df.to_csv('./s_server_df.csv', index=False)
# s_client_packets_df.to_csv('./s_client_packets_df.csv', index=False)
# print("Done. packets:", len(packets_rows), "client rows:", len(client_rows),
#       "perf rows:", len(client_perf_rows), "server rows:", len(server_rows))
