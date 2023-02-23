use integ8_sdk::GatewayError;
use integ8_sdk::Payload;
use integ8_sdk::PayloadBuilder;

#[no_mangle]
pub extern "C" fn execute(payload: &Payload) -> Result<Payload, GatewayError> {
    println!("Payload from lib {:?}", payload);
    let auth_key_header = Some("123456789");

    if auth_key_header.is_none() {
        return Err(GatewayError::new(
            "Auth Key".to_string(),
            "Auth key not found in header".to_string(),
            401,
        ));
    }

    let auth_key = auth_key_header.unwrap();

    if auth_key != "123456789" {
        return Err(GatewayError::new(
            "Auth Key".to_string(),
            "Auth key not valid".to_string(),
            401,
        ));
    }

    Ok(PayloadBuilder::default().build().unwrap())
}
