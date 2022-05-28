extern crate rand;
extern crate ed25519_dalek;

use ed25519_dalek::Verifier;

#[repr(C)]
pub struct Buffer {
    data: *mut u8,
    len: usize,
}

#[no_mangle]
pub extern fn okc_ed25519_gen_keypair() -> Buffer {
    use rand::rngs::OsRng;
    use ed25519_dalek::Keypair;

    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let mut buf = vec![0; ed25519_dalek::KEYPAIR_LENGTH].into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len();
    std::mem::forget(buf);

    unsafe { std::ptr::copy(&keypair.to_bytes()[0], data, ed25519_dalek::KEYPAIR_LENGTH); }

    Buffer { data, len }
}

#[no_mangle]
pub extern fn okc_ed25519_sign(keypair: Buffer, msg: Buffer) -> Buffer {
    use ed25519_dalek::Keypair;
    let raw_keypair = unsafe { std::slice::from_raw_parts_mut(keypair.data, keypair.len) };
    let keypair = Keypair::from_bytes(raw_keypair).unwrap();

    use ed25519_dalek::{Signature, Signer};
    let raw_msg = unsafe { std::slice::from_raw_parts_mut(msg.data, msg.len) };
    let signature: Signature = keypair.sign(raw_msg);


    let mut buf = vec![0; ed25519_dalek::SIGNATURE_LENGTH].into_boxed_slice();
    let data = buf.as_mut_ptr();
    let len = buf.len();
    std::mem::forget(buf);

    unsafe { std::ptr::copy(&signature.to_bytes()[0], data, ed25519_dalek::SIGNATURE_LENGTH); }

    Buffer { data, len }
}


#[no_mangle]
pub extern fn okc_ed25519_verify(pubkey: Buffer, msg: Buffer, signature: Buffer) -> bool {
    let raw_pub_key = unsafe { std::slice::from_raw_parts_mut(pubkey.data, pubkey.len) };
    let pub_key = ed25519_dalek::PublicKey::from_bytes(raw_pub_key).unwrap();

    let raw_msg = unsafe { std::slice::from_raw_parts_mut(msg.data, msg.len) };

    let raw_signature = unsafe { std::slice::from_raw_parts_mut(signature.data, signature.len) };
    let signature: ed25519_dalek::Signature = ed25519_dalek::Signature::from_bytes(raw_signature).unwrap();

    pub_key.verify(raw_msg, &signature).is_ok()
}

#[no_mangle]
pub extern fn free_buf(buf: Buffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
