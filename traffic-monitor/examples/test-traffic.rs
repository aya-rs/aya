use std::{
    net::{SocketAddr, UdpSocket},
    thread,
    time::Duration,
};

/// Simple traffic generator for testing the traffic monitor
/// This generates UDP traffic from various source addresses to test filtering
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Traffic generator starting...");
    
    // Test addresses - some permitted (localhost, private), some not
    let test_addresses = vec![
        ("127.0.0.1", true),   // Localhost - should be permitted
        ("192.168.1.100", true), // Private - should be permitted  
        ("10.0.0.50", true),   // Private - should be permitted
        ("8.8.8.8", false),    // Google DNS - should NOT be permitted
        ("1.1.1.1", false),    // Cloudflare DNS - should NOT be permitted
        ("172.16.0.10", true), // Private - should be permitted
    ];
    
    let target_port = 8080;
    
    for (i, (addr, should_be_permitted)) in test_addresses.iter().enumerate() {
        println!("Sending test packet from {} (expected: {})", 
                addr, if *should_be_permitted { "PERMITTED" } else { "NOT PERMITTED" });
        
        // This is a simulation - in practice you'd need to actually bind to these addresses
        // For testing purposes, we'll just log what we would do
        
        // Try to bind to the address (this will only work for local addresses)
        match format!("{}:0", addr).parse::<SocketAddr>() {
            Ok(bind_addr) => {
                if let Ok(socket) = UdpSocket::bind(bind_addr) {
                    let target = format!("127.0.0.1:{}", target_port);
                    let message = format!("Test packet {} from {}", i, addr);
                    
                    match socket.send_to(message.as_bytes(), &target) {
                        Ok(_) => println!("  ✓ Sent packet from {}", addr),
                        Err(e) => println!("  ✗ Failed to send from {}: {}", addr, e),
                    }
                } else {
                    println!("  ⚠ Cannot bind to {} (probably not local)", addr);
                }
            }
            Err(e) => {
                println!("  ✗ Invalid address {}: {}", addr, e);
            }
        }
        
        thread::sleep(Duration::from_millis(500));
    }
    
    println!("\nTraffic generation complete.");
    println!("Note: Only packets from addresses that can be bound locally will actually be sent.");
    println!("To fully test external addresses, you would need to:");
    println!("1. Use a network namespace or container");
    println!("2. Configure routing to make external addresses locally routable");
    println!("3. Use raw sockets (requires root privileges)");
    
    Ok(())
}