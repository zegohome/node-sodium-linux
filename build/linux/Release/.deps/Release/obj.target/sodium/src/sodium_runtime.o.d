cmd_Release/obj.target/sodium/src/sodium_runtime.o := g++ '-DNODE_GYP_MODULE_NAME=sodium' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/root/.node-gyp/0.12.15/include/node -I/root/.node-gyp/0.12.15/src -I/root/.node-gyp/0.12.15/deps/uv/include -I/root/.node-gyp/0.12.15/deps/v8/include -I../src/include -I../deps/build/include -I../node_modules/nan  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -fPIC -O3 -ffunction-sections -fdata-sections -fno-tree-vrp -fno-tree-sink -fno-omit-frame-pointer -fno-rtti -fno-exceptions -MMD -MF ./Release/.deps/Release/obj.target/sodium/src/sodium_runtime.o.d.raw   -c -o Release/obj.target/sodium/src/sodium_runtime.o ../src/sodium_runtime.cc
Release/obj.target/sodium/src/sodium_runtime.o: ../src/sodium_runtime.cc \
 ../src/include/node_sodium.h /root/.node-gyp/0.12.15/include/node/node.h \
 /root/.node-gyp/0.12.15/include/node/v8.h \
 /root/.node-gyp/0.12.15/include/node/v8stdint.h \
 /root/.node-gyp/0.12.15/include/node/v8config.h \
 /root/.node-gyp/0.12.15/include/node/node_version.h \
 /root/.node-gyp/0.12.15/include/node/node_buffer.h \
 /root/.node-gyp/0.12.15/include/node/node.h \
 /root/.node-gyp/0.12.15/include/node/smalloc.h ../node_modules/nan/nan.h \
 /root/.node-gyp/0.12.15/include/node/node_version.h \
 /root/.node-gyp/0.12.15/include/node/uv.h \
 /root/.node-gyp/0.12.15/include/node/uv-errno.h \
 /root/.node-gyp/0.12.15/include/node/uv-version.h \
 /root/.node-gyp/0.12.15/include/node/uv-unix.h \
 /root/.node-gyp/0.12.15/include/node/uv-threadpool.h \
 /root/.node-gyp/0.12.15/include/node/uv-linux.h \
 /root/.node-gyp/0.12.15/include/node/node_object_wrap.h \
 ../node_modules/nan/nan_callbacks.h \
 ../node_modules/nan/nan_callbacks_12_inl.h \
 ../node_modules/nan/nan_maybe_pre_43_inl.h \
 ../node_modules/nan/nan_converters.h \
 ../node_modules/nan/nan_converters_pre_43_inl.h \
 ../node_modules/nan/nan_new.h \
 ../node_modules/nan/nan_implementation_12_inl.h \
 ../node_modules/nan/nan_persistent_12_inl.h \
 ../node_modules/nan/nan_weak.h ../node_modules/nan/nan_object_wrap.h \
 ../node_modules/nan/nan_typedarray_contents.h \
 ../deps/build/include/sodium.h ../deps/build/include/sodium/core.h \
 ../deps/build/include/sodium/export.h \
 ../deps/build/include/sodium/crypto_aead_aes256gcm.h \
 ../deps/build/include/sodium/crypto_aead_chacha20poly1305.h \
 ../deps/build/include/sodium/crypto_auth.h \
 ../deps/build/include/sodium/crypto_auth_hmacsha512256.h \
 ../deps/build/include/sodium/crypto_auth_hmacsha512.h \
 ../deps/build/include/sodium/crypto_hash_sha512.h \
 ../deps/build/include/sodium/crypto_auth_hmacsha256.h \
 ../deps/build/include/sodium/crypto_hash_sha256.h \
 ../deps/build/include/sodium/crypto_auth_hmacsha512.h \
 ../deps/build/include/sodium/crypto_auth_hmacsha512256.h \
 ../deps/build/include/sodium/crypto_box.h \
 ../deps/build/include/sodium/crypto_box_curve25519xsalsa20poly1305.h \
 ../deps/build/include/sodium/crypto_box_curve25519xsalsa20poly1305.h \
 ../deps/build/include/sodium/crypto_core_hsalsa20.h \
 ../deps/build/include/sodium/crypto_core_hchacha20.h \
 ../deps/build/include/sodium/crypto_core_salsa20.h \
 ../deps/build/include/sodium/crypto_core_salsa2012.h \
 ../deps/build/include/sodium/crypto_core_salsa208.h \
 ../deps/build/include/sodium/crypto_generichash.h \
 ../deps/build/include/sodium/crypto_generichash_blake2b.h \
 ../deps/build/include/sodium/crypto_generichash_blake2b.h \
 ../deps/build/include/sodium/crypto_hash.h \
 ../deps/build/include/sodium/crypto_hash_sha256.h \
 ../deps/build/include/sodium/crypto_hash_sha512.h \
 ../deps/build/include/sodium/crypto_onetimeauth.h \
 ../deps/build/include/sodium/crypto_onetimeauth_poly1305.h \
 ../deps/build/include/sodium/crypto_onetimeauth_poly1305.h \
 ../deps/build/include/sodium/crypto_pwhash.h \
 ../deps/build/include/sodium/crypto_pwhash_argon2i.h \
 ../deps/build/include/sodium/crypto_pwhash_argon2i.h \
 ../deps/build/include/sodium/crypto_pwhash_scryptsalsa208sha256.h \
 ../deps/build/include/sodium/crypto_scalarmult.h \
 ../deps/build/include/sodium/crypto_scalarmult_curve25519.h \
 ../deps/build/include/sodium/crypto_scalarmult_curve25519.h \
 ../deps/build/include/sodium/crypto_secretbox.h \
 ../deps/build/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
 ../deps/build/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
 ../deps/build/include/sodium/crypto_shorthash.h \
 ../deps/build/include/sodium/crypto_shorthash_siphash24.h \
 ../deps/build/include/sodium/crypto_shorthash_siphash24.h \
 ../deps/build/include/sodium/crypto_sign.h \
 ../deps/build/include/sodium/crypto_sign_ed25519.h \
 ../deps/build/include/sodium/crypto_sign_ed25519.h \
 ../deps/build/include/sodium/crypto_stream.h \
 ../deps/build/include/sodium/crypto_stream_xsalsa20.h \
 ../deps/build/include/sodium/crypto_stream_aes128ctr.h \
 ../deps/build/include/sodium/crypto_stream_chacha20.h \
 ../deps/build/include/sodium/crypto_stream_salsa20.h \
 ../deps/build/include/sodium/crypto_stream_salsa2012.h \
 ../deps/build/include/sodium/crypto_stream_salsa208.h \
 ../deps/build/include/sodium/crypto_stream_xsalsa20.h \
 ../deps/build/include/sodium/crypto_verify_16.h \
 ../deps/build/include/sodium/crypto_verify_32.h \
 ../deps/build/include/sodium/crypto_verify_64.h \
 ../deps/build/include/sodium/randombytes.h \
 ../deps/build/include/sodium/randombytes_salsa20_random.h \
 ../deps/build/include/sodium/randombytes.h \
 ../deps/build/include/sodium/randombytes_sysrandom.h \
 ../deps/build/include/sodium/runtime.h \
 ../deps/build/include/sodium/utils.h \
 ../deps/build/include/sodium/version.h
../src/sodium_runtime.cc:
../src/include/node_sodium.h:
/root/.node-gyp/0.12.15/include/node/node.h:
/root/.node-gyp/0.12.15/include/node/v8.h:
/root/.node-gyp/0.12.15/include/node/v8stdint.h:
/root/.node-gyp/0.12.15/include/node/v8config.h:
/root/.node-gyp/0.12.15/include/node/node_version.h:
/root/.node-gyp/0.12.15/include/node/node_buffer.h:
/root/.node-gyp/0.12.15/include/node/node.h:
/root/.node-gyp/0.12.15/include/node/smalloc.h:
../node_modules/nan/nan.h:
/root/.node-gyp/0.12.15/include/node/node_version.h:
/root/.node-gyp/0.12.15/include/node/uv.h:
/root/.node-gyp/0.12.15/include/node/uv-errno.h:
/root/.node-gyp/0.12.15/include/node/uv-version.h:
/root/.node-gyp/0.12.15/include/node/uv-unix.h:
/root/.node-gyp/0.12.15/include/node/uv-threadpool.h:
/root/.node-gyp/0.12.15/include/node/uv-linux.h:
/root/.node-gyp/0.12.15/include/node/node_object_wrap.h:
../node_modules/nan/nan_callbacks.h:
../node_modules/nan/nan_callbacks_12_inl.h:
../node_modules/nan/nan_maybe_pre_43_inl.h:
../node_modules/nan/nan_converters.h:
../node_modules/nan/nan_converters_pre_43_inl.h:
../node_modules/nan/nan_new.h:
../node_modules/nan/nan_implementation_12_inl.h:
../node_modules/nan/nan_persistent_12_inl.h:
../node_modules/nan/nan_weak.h:
../node_modules/nan/nan_object_wrap.h:
../node_modules/nan/nan_typedarray_contents.h:
../deps/build/include/sodium.h:
../deps/build/include/sodium/core.h:
../deps/build/include/sodium/export.h:
../deps/build/include/sodium/crypto_aead_aes256gcm.h:
../deps/build/include/sodium/crypto_aead_chacha20poly1305.h:
../deps/build/include/sodium/crypto_auth.h:
../deps/build/include/sodium/crypto_auth_hmacsha512256.h:
../deps/build/include/sodium/crypto_auth_hmacsha512.h:
../deps/build/include/sodium/crypto_hash_sha512.h:
../deps/build/include/sodium/crypto_auth_hmacsha256.h:
../deps/build/include/sodium/crypto_hash_sha256.h:
../deps/build/include/sodium/crypto_auth_hmacsha512.h:
../deps/build/include/sodium/crypto_auth_hmacsha512256.h:
../deps/build/include/sodium/crypto_box.h:
../deps/build/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:
../deps/build/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:
../deps/build/include/sodium/crypto_core_hsalsa20.h:
../deps/build/include/sodium/crypto_core_hchacha20.h:
../deps/build/include/sodium/crypto_core_salsa20.h:
../deps/build/include/sodium/crypto_core_salsa2012.h:
../deps/build/include/sodium/crypto_core_salsa208.h:
../deps/build/include/sodium/crypto_generichash.h:
../deps/build/include/sodium/crypto_generichash_blake2b.h:
../deps/build/include/sodium/crypto_generichash_blake2b.h:
../deps/build/include/sodium/crypto_hash.h:
../deps/build/include/sodium/crypto_hash_sha256.h:
../deps/build/include/sodium/crypto_hash_sha512.h:
../deps/build/include/sodium/crypto_onetimeauth.h:
../deps/build/include/sodium/crypto_onetimeauth_poly1305.h:
../deps/build/include/sodium/crypto_onetimeauth_poly1305.h:
../deps/build/include/sodium/crypto_pwhash.h:
../deps/build/include/sodium/crypto_pwhash_argon2i.h:
../deps/build/include/sodium/crypto_pwhash_argon2i.h:
../deps/build/include/sodium/crypto_pwhash_scryptsalsa208sha256.h:
../deps/build/include/sodium/crypto_scalarmult.h:
../deps/build/include/sodium/crypto_scalarmult_curve25519.h:
../deps/build/include/sodium/crypto_scalarmult_curve25519.h:
../deps/build/include/sodium/crypto_secretbox.h:
../deps/build/include/sodium/crypto_secretbox_xsalsa20poly1305.h:
../deps/build/include/sodium/crypto_secretbox_xsalsa20poly1305.h:
../deps/build/include/sodium/crypto_shorthash.h:
../deps/build/include/sodium/crypto_shorthash_siphash24.h:
../deps/build/include/sodium/crypto_shorthash_siphash24.h:
../deps/build/include/sodium/crypto_sign.h:
../deps/build/include/sodium/crypto_sign_ed25519.h:
../deps/build/include/sodium/crypto_sign_ed25519.h:
../deps/build/include/sodium/crypto_stream.h:
../deps/build/include/sodium/crypto_stream_xsalsa20.h:
../deps/build/include/sodium/crypto_stream_aes128ctr.h:
../deps/build/include/sodium/crypto_stream_chacha20.h:
../deps/build/include/sodium/crypto_stream_salsa20.h:
../deps/build/include/sodium/crypto_stream_salsa2012.h:
../deps/build/include/sodium/crypto_stream_salsa208.h:
../deps/build/include/sodium/crypto_stream_xsalsa20.h:
../deps/build/include/sodium/crypto_verify_16.h:
../deps/build/include/sodium/crypto_verify_32.h:
../deps/build/include/sodium/crypto_verify_64.h:
../deps/build/include/sodium/randombytes.h:
../deps/build/include/sodium/randombytes_salsa20_random.h:
../deps/build/include/sodium/randombytes.h:
../deps/build/include/sodium/randombytes_sysrandom.h:
../deps/build/include/sodium/runtime.h:
../deps/build/include/sodium/utils.h:
../deps/build/include/sodium/version.h:
