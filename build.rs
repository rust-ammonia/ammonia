use html5ever::parse_document;
use html5ever::tendril::TendrilSink;
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use std::{fs, io::Write, path::Path};

const LINK_RELATIONS_PAGE: &str =
    "https://www.iana.org/assignments/link-relations/link-relations.xhtml";

fn main() {
    println!("main");

    let client = reqwest::blocking::Client::new();
    let html = client
        .get(LINK_RELATIONS_PAGE)
        .header(
            reqwest::header::USER_AGENT,
            "Mozilla/5.0 (compatible; CopilotBot/1.0)",
        )
        .send()
        .expect("Failed to fetch page")
        .text()
        .expect("Failed to read response text");

    let dom = parse_document(RcDom::default(), Default::default())
        .from_utf8()
        .read_from(&mut html.as_bytes())
        .expect("Failed to parse HTML");

    let rel_values = extract_rel_values(&dom);

    let output_text = rel_values.join("\n");

    let out_dir = Path::new("src/whitelists");
    fs::create_dir_all(out_dir).expect("Failed to create output directory");

    let mut file = fs::File::create(out_dir.join("rel.txt")).expect("Failed to create file");
    file.write_all(output_text.as_bytes())
        .expect("Failed to write file");
}

fn extract_rel_values(dom: &RcDom) -> Vec<String> {
    let mut rels = Vec::new();
    extract_rels(&dom.document, &mut rels);

    rels.sort();
    rels.dedup();
    rels
}

fn extract_rels(handle: &Handle, rels: &mut Vec<String>) {
    let node = handle;
    match &node.data {
        NodeData::Element { name, .. } => {
            if name.local.as_ref() == "tr" {
                if let Some(first_child) = node
                    .children
                    .take()
                    .iter()
                    .filter(|node| match &node.data {
                        NodeData::Element { name, .. } => name.local.as_ref() == "td",
                        _ => false,
                    })
                    .collect::<Vec<_>>()
                    .first()
                {
                    let text = get_text(first_child);
                    if !text.is_empty() {
                        rels.push(text);
                    }
                }
            }
        }
        _ => {}
    }

    for child in node.children.borrow().iter() {
        extract_rels(child, rels);
    }
}

fn get_text(node: &Handle) -> String {
    let mut result = String::new();
    collect_text(node, &mut result);
    result.trim().to_string()
}

fn collect_text(handle: &Handle, buffer: &mut String) {
    match &handle.data {
        NodeData::Text { contents } => {
            buffer.push_str(&contents.borrow());
        }
        _ => {
            for child in handle.children.borrow().iter() {
                collect_text(child, buffer);
            }
        }
    }
}
