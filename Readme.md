# Trustworthy & Accountable Function-as-a-Service 
This is the source code repository of the paper "S-FaaS: Trustworthy and Accountable Function-as-a-Service using Intel SGX", published at the 2019 ACM Cloud Computing Security Workshop. An early version of this paper can be viewed here on arxiv: https://arxiv.org/abs/1810.06080


# Installation

The enclave uses Duktape as JS Engine. If the project does not compile for you, you might have to generate the Duktape files for your own machine. Do this by downloading its code from https://github.com/svaarala/duktape and executing the configure.py in the tools folder. This generates the Duktape files that you can then place in the src/enclave/duktape folder.

Requirements are
```bash
sudo apt install libboost-program-options-dev libboost-system-dev libb64-dev
```

For the configuration file, run

```bash
python2 genconfig.py  --metadata ../config/ \
    --option-file ./duktape-config.yml \
    --output ./duk_config.h \
    --platform=linux --compiler=gcc \
    --architecture=x64 \
    duk-config-header
```

To create other files, run
```bash
python2 configure.py
    --option-file ~/git/sgx-js/js_app/duktape-config.yml \
    --output-directory ~/git/sgx-js/js_app/src/enclave/duktape \
    --platform=linux --compiler=clang \
    --architecture=x64

```

And place the resulting duk_config.h in the src/enclave/duktape directory, overwriting the pregenerated file.

## Changes to duktape
These changes are very similar to here: https://github.com/luckychain/node-secureworker/issues/10

duk_config:

1. Comment out line 261,262 (include of sys/params.h and sys/time.h)
2. Comment out #define DUK_USE_DATE_NOW_GETTIMEOFDAY , #define DUK_USE_DATE_TZO_GMTIME_R, #define DUK_USE_DATE_PRS_STRPTIME , #define DUK_USE_DATE_FMT_STRFTIME
3. Add OVERRIDE_DEFINES:

```clang
#define DUK_USE_DATE_GET_NOW(ctx)  -1
#define DUK_USE_DATE_GET_LOCAL_TZOFFSET(d) -1
```
4. In duk__format_parts_iso8601 : Rewrite calls to DUK_SNPRINTF into calls to DUK_SPRINTF (without N). As size, provide: (size_t) DUK_BI_DATE_ISO8601_BUFSIZE.

# Usage
```bash
# Open one console and prepare the js app
cd js_app
make all
# create a new key file named keys sealed
./js-tsx -n -p "keys.sealed" -v

# In another console, prepare the client input
cd tsx-py/tsx
python3 client.py -i ./js-files/hello_world.json -k ./js-files/keys.json -o ./js-files/enc.json -v

# Now run js app in first console
./js-tsx -r "keys.sealed" -x js-files/hello_world.js -i js-files/enc.json  -v



./app.exe -n -p ./keys.sealed -r ./keys.sealed -x js-files/hello_world.js -i js-files/hello_world.json
python3 client.py -i js-files/hello_world.json -v -k js-files/keys.json
```
Use -v and -d flags to show enclave logging
