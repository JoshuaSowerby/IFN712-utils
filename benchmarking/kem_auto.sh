all_pq_kems=("frodo640shake" "frodo976shake" "frodo1344shake" "bikel1" "bikel3" "bikel5" "mlkem512" "mlkem768" "mlkem1024" "hqc128" "hqc192" "hqc256")
all_cl_kems=("x25519" "x448" "secp256_r1" "secp384_r1" "secp521_r1")

all_hybrid_kems=("p256_frodo640shake" "x25519_frodo640shake" "x448_frodo640shake" "p384_frodo976shake" "x25519_frodo976shake" "x448_frodo976shake" "p521_frodo1344shake" "x25519_frodo1344shake" "x448_frodo1344shake" "p256_mlkem512" "x25519_mlkem512" "x448_mlkem512" "p384_mlkem768" "x25519_mlkem768" "x448_mlkem768" "p521_mlkem1024" "x25519_mlkem1024" "x448_mlkem1024" "p256_bikel1" "x25519_bikel1" "x448_bikel1" "p384_bikel3" "x25519_bikel3" "x448_bikel3" "p521_bikel5" "x25519_bikel5" "x448_bikel5" "p256_hqc128" "x25519_hqc128" "x448_hqc128" "p384_hqc192" "x25519_hqc192" "x448_hqc192" "p521_hqc256" "x25519_hqc256" "x448_hqc256")

#docker run --rm -it --cap-add=NET_ADMIN --cap-add=SYS_ADMIN -v "C:\Users\...\Desktop\openssl test\results:/logs" custom-oqs-provider-v3


# Classical signature types
all_cl_sigs=("rsa:3072") # "ed25519" "ed448")
# EC curves separated for dynamic generation
all_ec_curves=("prime256v1" "secp384r1" "secp521r1")

# find better values later
all_loss=(0 10 20)
all_delay=(5 25 200)
all_MTU=(1500 1280 576)

MAX_ITER=50

setup_namespaces(){
    #1. setup namespaces
    ip netns add client
    ip netns add server
    #2. create veth pair
    ip link add veth-client type veth peer name veth-server
    #3. move each veth into its namespace
    ip link set veth-client netns client
    ip link set veth-server netns server
    #4. Assign IPs
    ip netns exec client ip addr add 10.0.0.1/24 dev veth-client
    ip netns exec server ip addr add 10.0.0.2/24 dev veth-server
    #5. Bring up interfaces and loopback
    ip netns exec client ip link set lo up
    ip netns exec client ip link set veth-client up

    ip netns exec server ip link set lo up
    ip netns exec server ip link set veth-server up
}
network_settings(){
    local DELAY=$1
    local LOSS=$2
    local MTU=$3
    #delay and loss
    ip netns exec client tc qdisc replace dev veth-client root netem delay ${DELAY}ms loss ${LOSS}%
    ip netns exec server tc qdisc replace dev veth-server root netem delay ${DELAY}ms loss ${LOSS}%
    #mtu
    ip netns exec client ip link set dev veth-client mtu ${MTU}
    ip netns exec server ip link set dev veth-server mtu ${MTU}

}

s_client_loop(){
    local combo_dir="$1"
    local PORT="$2"
    local KEM="$3"

    local CAP_FILE
    local TCPDUMP_PID
    local PKT_COUNT
    local i

    for i in $(seq 1 "$MAX_ITER"); do
        printf "[%04d] Starting iteration\n" "$i" >> "$combo_dir/s_client.log"

        # only need to run tcpdump once as per combo as they should all be the same?
        if [ "$i" -eq 1 ]; then
            CAP_FILE="/${combo_dir}/capture_${i}.pcap"
            ip netns exec client tcpdump -i veth-client -U -w "$CAP_FILE" "tcp port $PORT" >/dev/null 2>&1 &
            TCPDUMP_PID=$!
            sleep 0.5
        fi

        # run client, feed no stdin and timeout to avoid hangs; use server IP inside namespace
        #TODO do can I do this without the tiemout and just exit when connection finished?
        START_NS=$(date +%s%N)
        STATS=$(ip netns exec client /usr/bin/time -v \
            openssl s_client -connect "10.0.0.2:$PORT" -groups "$KEM" -quiet < /dev/null \
            2>&1 > "$combo_dir/s_client.log") 2> >(grep -E "User time|System time|Elapsed|Percent of CPU|Maximum resident set size" \
                | while IFS= read -r line; do printf "[%04d] %s\n" "$i" "$line"; done >> "$combo_dir/s_client_perf.log") || true
        END_NS=$(date +%s%N)
        WALL_NS=$((END_NS - START_NS))
        WALL_S=$(awk "BEGIN:{print $WALL_NS/1000000000}")

        printf "[%04d] WALL_TIME_S=%s\n" "$i" "$WALL_S" >> "$combo_dir/s_client_perf.log"
        #tcpdump -r "$CAP_FILE" -n -c 1 -tttt # print last packet
        # stop tcpdump
        if [ "$i" -eq 1 ]; then
            sleep 0.5 # let tcdump flush

            kill "$TCPDUMP_PID" >/dev/null 2>&1
            wait "$TCPDUMP_PID" 2>/dev/null || true

            # count and show packets
            PKT_COUNT=$(tcpdump -r "$CAP_FILE" -n 2>/dev/null | wc -l)
            echo "[${i}] Packets: $PKT_COUNT" >> "$combo_dir/s_client_packets.log"
        fi

        # rm -f "$CAP_FILE"
        sleep 0.1
    done
}

start_server(){
    local SEQ=1
    #local SERVER_PID
    # Start server with sequence numbers in output
    ip netns exec server openssl s_server -cert "$certfile" -key "$keyfile" \
        -accept "$PORT" -quiet -groups "$hybrid_kem" \
        > >(while IFS= read -r line; do
                printf "[%04d] %s\n" "$SEQ" "$line"
                ((SEQ++))
            done > "$combo_dir/s_server.log") 2>&1 &
    SERVER_PID=$!
    sleep 1
}

#?. run
determine_cert_key_files(){
    if [[ "$cl_sig" == ec- ]]; then
        curve="${cl_sig#ec_}"
        keyfile="key_ec_${curve}.pem"
        certfile="cert_ec_${curve}.pem"
        signame="$cl_sig"
        openssl ecparam -name $curve -genkey -noout -out $keyfile
        openssl req -new -x509 -key $keyfile -out $certfile -days 365 -subj "/CN=localhost"

    else
        clean_sig="${cl_sig//:/-}"   # replace ':' with '_'
        keyfile="key_${clean_sig}.pem"
        certfile="cert_${clean_sig}.pem"
        signame="$clean_sig"
        openssl req -x509 -newkey "$cl_sig" \
        -keyout $keyfile -out $certfile \
        -days 365 -nodes -subj "/CN=oqs-server"
    fi
    
}

setup_namespaces
for delay in "${all_delay[@]}"; do
    for loss in "${all_loss[@]}"; do
        for mtu in "${all_MTU[@]}"; do
            network_settings $delay $loss $mtu
            for cl_sig in "${all_cl_sigs[@]}"; do # "${all_ec_curves[@]/#/ec-}"; do
                # Determine key/cert file names
                # changes curve, keyfile, certfile, signame
                determine_cert_key_files

                for hybrid_kem in "${all_hybrid_kems[@]}"; do
                    arr_kem=(${hybrid_kem//_/ })
                    cl_kem=${arr_kem[0]}
                    pq_kem=${arr_kem[1]}
                    combo_dir="logs/${signame}_${hybrid_kem}_delay${delay}_loss${loss}_mtu${mtu}"
                    mkdir -p "$combo_dir"

                    echo "Starting test: $signame / $hybrid_kem"

                    PORT=$((4000 + RANDOM % 1000))
                    # start server, changes $certfile $keyfile $PORT $hybrid_kem, $SERVER_PID
                    start_server

                    # Run client iterations with sequence numbers
                    s_client_loop $combo_dir $PORT $hybrid_kem

                    # Kill server if running
                    if [ ! -z "$SERVER_PID" ] && ps -p $SERVER_PID > /dev/null; then
                        kill $SERVER_PID
                    fi
                    sleep 1
                done
            done
        done
    done
done

