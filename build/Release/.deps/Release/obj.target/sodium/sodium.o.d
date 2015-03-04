cmd_Release/obj.target/sodium/sodium.o := g++ '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/home/ec2-user/.node-gyp/0.10.36/src -I/home/ec2-user/.node-gyp/0.10.36/deps/uv/include -I/home/ec2-user/.node-gyp/0.10.36/deps/v8/include -I../deps/libsodium-1.0.0/src/libsodium/include -I../node_modules/nan  -fPIC -Wall -Wextra -Wno-unused-parameter -pthread -m64 -O2 -fno-strict-aliasing -fno-tree-vrp -fno-omit-frame-pointer -fno-rtti -fno-exceptions -MMD -MF ./Release/.deps/Release/obj.target/sodium/sodium.o.d.raw  -c -o Release/obj.target/sodium/sodium.o ../sodium.cc
Release/obj.target/sodium/sodium.o: ../sodium.cc \
 /home/ec2-user/.node-gyp/0.10.36/src/node.h \
 /home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv.h \
 /home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv-private/uv-unix.h \
 /home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv-private/ngx-queue.h \
 /home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv-private/uv-linux.h \
 /home/ec2-user/.node-gyp/0.10.36/deps/v8/include/v8.h \
 /home/ec2-user/.node-gyp/0.10.36/deps/v8/include/v8stdint.h \
 /home/ec2-user/.node-gyp/0.10.36/src/node_object_wrap.h \
 /home/ec2-user/.node-gyp/0.10.36/src/node.h \
 /home/ec2-user/.node-gyp/0.10.36/src/node_buffer.h \
 ../node_modules/nan/nan.h \
 /home/ec2-user/.node-gyp/0.10.36/src/node_version.h \
 /home/ec2-user/.node-gyp/0.10.36/src/node_object_wrap.h \
 ../node_modules/nan/nan_new.h \
 ../node_modules/nan/nan_implementation_pre_12_inl.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/core.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/export.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha512.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha256.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha256.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_box.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_hsalsa20.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_salsa20.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_salsa2012.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_salsa208.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_generichash.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_generichash_blake2b.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_generichash_blake2b.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha256.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha512.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_onetimeauth.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_pwhash_scryptsalsa208sha256.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_scalarmult.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_secretbox.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_shorthash.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_shorthash_siphash24.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_shorthash_siphash24.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_sign.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_sign_ed25519.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_sign_ed25519.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_xsalsa20.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_aes128ctr.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_chacha20.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_salsa20.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_salsa2012.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_salsa208.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_xsalsa20.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_verify_16.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_verify_32.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_verify_64.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/randombytes.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/randombytes_salsa20_random.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/randombytes_sysrandom.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/runtime.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/utils.h \
 ../deps/libsodium-1.0.0/src/libsodium/include/sodium/version.h
../sodium.cc:
/home/ec2-user/.node-gyp/0.10.36/src/node.h:
/home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv.h:
/home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv-private/uv-unix.h:
/home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv-private/ngx-queue.h:
/home/ec2-user/.node-gyp/0.10.36/deps/uv/include/uv-private/uv-linux.h:
/home/ec2-user/.node-gyp/0.10.36/deps/v8/include/v8.h:
/home/ec2-user/.node-gyp/0.10.36/deps/v8/include/v8stdint.h:
/home/ec2-user/.node-gyp/0.10.36/src/node_object_wrap.h:
/home/ec2-user/.node-gyp/0.10.36/src/node.h:
/home/ec2-user/.node-gyp/0.10.36/src/node_buffer.h:
../node_modules/nan/nan.h:
/home/ec2-user/.node-gyp/0.10.36/src/node_version.h:
/home/ec2-user/.node-gyp/0.10.36/src/node_object_wrap.h:
../node_modules/nan/nan_new.h:
../node_modules/nan/nan_implementation_pre_12_inl.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/core.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/export.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_aead_chacha20poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha512.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha256.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha256.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_box.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_hsalsa20.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_salsa20.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_salsa2012.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_core_salsa208.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_generichash.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_generichash_blake2b.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_generichash_blake2b.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha256.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_hash_sha512.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_onetimeauth.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_scalarmult.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_secretbox.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_shorthash.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_shorthash_siphash24.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_shorthash_siphash24.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_sign.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_sign_ed25519.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_sign_ed25519.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_xsalsa20.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_aes128ctr.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_chacha20.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_salsa20.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_salsa2012.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_salsa208.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_stream_xsalsa20.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_verify_16.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_verify_32.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/crypto_verify_64.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/randombytes.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/randombytes_salsa20_random.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/randombytes_sysrandom.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/runtime.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/utils.h:
../deps/libsodium-1.0.0/src/libsodium/include/sodium/version.h:
