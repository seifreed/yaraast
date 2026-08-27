FROM gcr.io/oss-fuzz-base/base-builder-python

RUN python3 -m pip install --no-cache-dir pyinstaller
RUN git clone --depth 1 https://github.com/seifreed/yaraast.git "$SRC/yaraast"
WORKDIR "$SRC/yaraast"
