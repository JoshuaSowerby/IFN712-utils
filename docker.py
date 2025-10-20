import math
all_sigs=(
    ("p256_mldsa44",
    "rsa3072_mldsa44"),
    ("p256_falcon512",
    "rsa3072_falcon512"),
    ("sphincsshake128fsimple",
    "p256_sphincsshake128fsimple"),
    ("rsa3072_sphincsshake128fsimple",
    "p256_mayo1"),
    ("rsa3072_mayo1",
    "p256_snova2454shake",
    "rsa3072_snova2454shake"))
#5
all_kems=(
    ("p256_frodo640shake",
    "x25519_frodo640shake"),
    ("x448_frodo640shake",
    "p256_mlkem512"),
    ("x25519_mlkem512",
    "x448_mlkem512"),
    ("p256_bikel1",
    "x25519_bikel1"),
    ("x448_bikel1",
    "p256_hqc128"),
    ("x25519_hqc128",
    "x448_hqc128")
)

max_cores=11

size={"l":[0.5,'256m'],"m":[0.25,"128m"],"s":[0.125,"64m"],"t":[0.0625,"32m"]}
path="E:\\Projects\\uni_sh\\results"
aorb="b.sh"
cpuset=0
for i in size:
    cpu,mem=size[i]
    for sig_subset in all_sigs:
        for kem_subset in all_kems:
            print(f'docker run -d '+
                f'--cap-add=NET_ADMIN --cap-add=SYS_ADMIN '+
                f'--cpus="{cpu}" --memory="{mem}" --memory-swap="{mem}" --cpuset-cpus="{int(math.floor(cpuset))}"  '+
                f'-e ALL_SIGS="{' '.join(sig_subset)}" '+
                f'-e ALL_KEMS="{' '.join(kem_subset)}" '+
                f'-e ALL_DELAY="{"5 25 100"}" '+
                f'-e ALL_LOSS="{"0 1 5"}" '+
                f'-e ALL_MTU="{"1500 1280 576"}" '+
                f'-v "{path}\\{i}_logs:/logs" '+
                f'ifn712 /bin/bash {aorb}\n')
            # if cpuset==5:
            #     cpuset+=1
            cpuset+=cpu
            if cpuset>max_cores:
                print(f"\n{(("#"*100)+'\n')*4}\n")
                cpuset=0