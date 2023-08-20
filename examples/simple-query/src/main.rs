use huiz::whois;

fn main() {
    let domain = "example.com";
    let r = whois(domain).unwrap();
    println!("{:?}", r)
}
