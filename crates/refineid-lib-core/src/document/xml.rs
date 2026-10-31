// Copyright 2026 Petri Koistinen
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! A small XML reader for signature files, and Exclusive XML
//! Canonicalization over one element subtree.
//!
//! The reader accepts the XML an `XAdES` signature file is made of:
//! elements with namespaces, attributes, character data, `CDATA`
//! sections, the five predefined entity references and character
//! references, comments and processing instructions. Every element
//! records the byte range it occupies in the source. A document type
//! declaration, any other entity reference, an encoding other than
//! UTF-8 and every namespace misuse are refused: `ETSI EN 319 132-1`
//! signatures carry none of them, and a reader that resolves less than
//! the producer wrote would digest different bytes.
//!
//! The canonicaliser renders one element and its descendants as
//! Exclusive XML Canonicalization 1.0 does, with or without comments,
//! and without an `InclusiveNamespaces PrefixList`.
//!
//! # Conformance
//!
//! - W3C XML 1.0 (Fifth Edition) <https://www.w3.org/TR/xml/>: sec.2.2
//!   characters, sec.2.11 end-of-line handling, sec.3.3.3 attribute
//!   value normalisation (every attribute is `CDATA` without a DTD),
//!   sec.4.1 character and entity references, sec.4.6 the predefined
//!   entities.
//! - W3C Namespaces in XML 1.0 (Third Edition)
//!   <https://www.w3.org/TR/xml-names/>: sec.3 declaring namespaces,
//!   sec.6 applying them to elements and attributes.
//! - W3C Canonical XML 1.0 <https://www.w3.org/TR/xml-c14n/> sec.2.2
//!   and sec.2.3: UTF-8, end tags for empty elements, attribute order,
//!   the escaping of attribute values and text, comments and
//!   processing instructions.
//! - W3C Exclusive XML Canonicalization 1.0
//!   <https://www.w3.org/TR/xml-exc-c14n/> sec.3: a namespace
//!   declaration is rendered on the outermost element of the subset
//!   that visibly utilises its prefix, and `xml:` attributes are not
//!   inherited from ancestors.

use core::ops::Range;

/// The namespace the `xml` prefix is bound to by definition
/// (Namespaces in XML 1.0 sec.3).
pub const NAMESPACE_XML: &str = "http://www.w3.org/XML/1998/namespace";

/// The namespace the `xmlns` prefix is bound to by definition
/// (Namespaces in XML 1.0 sec.3).
const NAMESPACE_XMLNS: &str = "http://www.w3.org/2000/xmlns/";

/// The prefix bound to [`NAMESPACE_XML`].
const PREFIX_XML: &str = "xml";

/// The attribute name, or prefix, of a namespace declaration.
const PREFIX_XMLNS: &str = "xmlns";

/// Deepest element nesting accepted. A signature file nests about ten
/// levels deep; the bound keeps the recursive canonicaliser's stack
/// small whatever the input.
const MAX_DEPTH: usize = 128;

/// The byte order mark a UTF-8 document may start with (XML 1.0
/// sec.4.3.3).
const BYTE_ORDER_MARK: char = '\u{FEFF}';

/// Opens an XML declaration (XML 1.0 sec.2.8).
const XML_DECLARATION_OPEN: &str = "<?xml";

/// Opens a document type declaration (XML 1.0 sec.2.8).
const DOCTYPE_OPEN: &str = "<!DOCTYPE";

/// Opens a comment (XML 1.0 sec.2.5).
const COMMENT_OPEN: &str = "<!--";

/// Closes a comment.
const COMMENT_CLOSE: &str = "-->";

/// Opens a `CDATA` section (XML 1.0 sec.2.7).
const CDATA_OPEN: &str = "<![CDATA[";

/// Closes a `CDATA` section.
const CDATA_CLOSE: &str = "]]>";

/// Opens a processing instruction (XML 1.0 sec.2.6).
const PI_OPEN: &str = "<?";

/// Closes a processing instruction or the XML declaration.
const PI_CLOSE: &str = "?>";

/// Opens an end tag (XML 1.0 sec.3.1).
const END_TAG_OPEN: &str = "</";

/// Closes an empty-element tag (XML 1.0 sec.3.1).
const EMPTY_TAG_CLOSE: &str = "/>";

/// Prefix of a hexadecimal character reference (XML 1.0 sec.4.1).
const CHAR_REF_HEX: &str = "#x";

/// Prefix of a decimal character reference.
const CHAR_REF_DECIMAL: &str = "#";

/// Radix of a hexadecimal character reference.
const RADIX_HEX: u32 = 16;

/// Radix of a decimal character reference.
const RADIX_DECIMAL: u32 = 10;

/// Lower bound of the first `Char` range above the control characters
/// (XML 1.0 sec.2.2 production 2).
const CHAR_RANGE_1_START: char = '\u{20}';

/// Upper bound of the first `Char` range, below the surrogates.
const CHAR_RANGE_1_END: char = '\u{D7FF}';

/// Lower bound of the second `Char` range, above the surrogates.
const CHAR_RANGE_2_START: char = '\u{E000}';

/// Upper bound of the second `Char` range; U+FFFE and U+FFFF are not
/// characters.
const CHAR_RANGE_2_END: char = '\u{FFFD}';

/// Lower bound of the supplementary-plane `Char` range.
const CHAR_RANGE_3_START: char = '\u{10000}';

/// The encoding name the XML declaration may carry (XML 1.0 sec.4.3.3).
const ENCODING_UTF8: &str = "UTF-8";

/// Why a document did not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XmlError {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The text is not well-formed XML, or misuses namespaces.
    Malformed(&'static str),
    /// Well-formed XML using a feature this reader refuses.
    Unsupported(&'static str),
    /// Elements nest deeper than this reader accepts.
    TooDeep,
}

impl core::fmt::Display for XmlError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotUtf8 => f.write_str("the XML is not UTF-8"),
            Self::Malformed(what) => write!(f, "malformed XML: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported XML: {what}"),
            Self::TooDeep => f.write_str("XML elements nest too deeply"),
        }
    }
}

impl core::error::Error for XmlError {}

/// Whether canonicalisation keeps comments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comments {
    /// `http://www.w3.org/2001/10/xml-exc-c14n#`.
    Omitted,
    /// `http://www.w3.org/2001/10/xml-exc-c14n#WithComments`.
    Retained,
}

/// One parsed attribute, namespace declarations excluded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Attribute {
    /// The prefix as written.
    prefix: Option<String>,
    /// The local part of the name.
    local: String,
    /// The namespace the prefix resolves to; `None` for an unprefixed
    /// attribute, which is in no namespace.
    namespace: Option<String>,
    /// The normalised value, references resolved.
    value: String,
}

/// One namespace declaration made on an element.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Declaration {
    /// The declared prefix; `None` for the default namespace.
    prefix: Option<String>,
    /// The namespace name; empty only when undeclaring the default.
    uri: String,
}

/// One child of an element.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    /// A child element, by index into the document's elements.
    Element(usize),
    /// Character data, references resolved and line ends normalised.
    Text(String),
    /// A comment's text.
    Comment(String),
    /// A processing instruction's target and data.
    ProcessingInstruction {
        /// The target name.
        target: String,
        /// The data after the separating whitespace; may be empty.
        data: String,
    },
}

/// One parsed element.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ElementData {
    /// The prefix as written.
    prefix: Option<String>,
    /// The local part of the name.
    local: String,
    /// The namespace the element is in, if any.
    namespace: Option<String>,
    /// The attributes, in source order.
    attributes: Vec<Attribute>,
    /// The namespace declarations made on this element.
    declarations: Vec<Declaration>,
    /// The children, in document order.
    children: Vec<Node>,
    /// The enclosing element.
    parent: Option<usize>,
    /// The bytes of the source the element occupies, start tag through
    /// end tag.
    span: Range<usize>,
}

/// A parsed XML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlDocument {
    /// The source text.
    source: String,
    /// Every element, in document order; the first is the root.
    elements: Vec<ElementData>,
}

impl XmlDocument {
    /// Parse a complete document.
    ///
    /// # Errors
    /// [`XmlError`] when the bytes are not UTF-8, not well-formed, use
    /// a refused feature, or nest deeper than this reader accepts.
    pub fn parse(source: Vec<u8>) -> Result<Self, XmlError> {
        let source = String::from_utf8(source).map_err(|_ignored| XmlError::NotUtf8)?;
        let elements = Parser::new(&source).document()?;
        Ok(Self { source, elements })
    }

    /// The document element.
    #[must_use]
    pub const fn root(&self) -> ElementRef<'_> {
        ElementRef {
            document: self,
            index: 0,
        }
    }

    /// Every element, in document order.
    pub fn elements(&self) -> impl Iterator<Item = ElementRef<'_>> {
        (0..self.elements.len()).map(|index| ElementRef {
            document: self,
            index,
        })
    }

    /// The source text the document was parsed from.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// The element at `index`. Indices come from this document's own
    /// nodes, so the lookup cannot miss.
    fn data(&self, index: usize) -> Option<&ElementData> {
        self.elements.get(index)
    }
}

/// One element of a parsed document.
#[derive(Debug, Clone, Copy)]
pub struct ElementRef<'a> {
    /// The document the element belongs to.
    document: &'a XmlDocument,
    /// Its index in the document's elements.
    index: usize,
}

impl PartialEq for ElementRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.document, other.document) && self.index == other.index
    }
}

impl Eq for ElementRef<'_> {}

impl<'a> ElementRef<'a> {
    /// The element's parsed data.
    #[expect(
        clippy::expect_used,
        reason = "an ElementRef is only built from an index of its own document's element arena"
    )]
    fn data(&self) -> &'a ElementData {
        self.document
            .data(self.index)
            .expect("invariant: element index from its own document")
    }

    /// The namespace the element is in, if any.
    #[must_use]
    pub fn namespace(&self) -> Option<&'a str> {
        self.data().namespace.as_deref()
    }

    /// The local part of the element's name.
    #[must_use]
    pub fn local_name(&self) -> &'a str {
        &self.data().local
    }

    /// Whether the element has this namespace and local name.
    #[must_use]
    pub fn is(&self, namespace: &str, local: &str) -> bool {
        self.namespace() == Some(namespace) && self.local_name() == local
    }

    /// The value of the attribute with this local name and no
    /// namespace.
    #[must_use]
    pub fn attribute(&self, local: &str) -> Option<&'a str> {
        self.data()
            .attributes
            .iter()
            .find(|attribute| attribute.namespace.is_none() && attribute.local == local)
            .map(|attribute| attribute.value.as_str())
    }

    /// The enclosing element.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        self.data().parent.map(|index| Self {
            document: self.document,
            index,
        })
    }

    /// The child elements, in document order.
    pub fn children(self) -> impl Iterator<Item = ElementRef<'a>> + 'a {
        let document = self.document;
        self.data()
            .children
            .iter()
            .filter_map(move |node| match node {
                Node::Element(index) => Some(ElementRef {
                    document,
                    index: *index,
                }),
                Node::Text(_) | Node::Comment(_) | Node::ProcessingInstruction { .. } => None,
            })
    }

    /// The child elements with this namespace and local name.
    pub fn children_named(
        self,
        namespace: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = ElementRef<'a>> + 'a {
        self.children()
            .filter(move |child| child.is(namespace, local))
    }

    /// The first child element with this namespace and local name.
    #[must_use]
    pub fn child(&self, namespace: &'a str, local: &'a str) -> Option<Self> {
        self.children_named(namespace, local).next()
    }

    /// The element and every element inside it, in document order.
    pub fn descendants(self) -> impl Iterator<Item = ElementRef<'a>> + 'a {
        let document = self.document;
        let root = self;
        let end = self.data().span.end;
        let start = self.index;
        // Elements are stored in document order, so a subtree is the
        // contiguous run of elements that start inside its span.
        (start..document.elements.len())
            .map(move |index| ElementRef { document, index })
            .take_while(move |element| element == &root || element.data().span.start < end)
    }

    /// The concatenated character data of the element's direct
    /// children.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for node in &self.data().children {
            if let Node::Text(text) = node {
                out.push_str(text);
            }
        }
        out
    }

    /// The bytes of the source the element occupies, from the `<` of
    /// its start tag through the `>` of its end tag.
    #[must_use]
    pub fn span(&self) -> Range<usize> {
        self.data().span.clone()
    }

    /// The namespace `prefix` resolves to at this element: its own
    /// declarations, then its ancestors'. `None` for the default
    /// namespace means no default is in scope.
    fn resolve(&self, prefix: Option<&str>) -> Option<&'a str> {
        ResolveAt {
            elements: &self.document.elements,
            index: self.index,
        }
        .resolve(prefix)
    }

    /// The element and its descendants under Exclusive XML
    /// Canonicalization 1.0, without an inclusive prefix list.
    ///
    /// W3C xml-exc-c14n sec.3 over the node set of this subtree (the
    /// form a same-document reference with an exclusive canonicalisation
    /// transform yields), rendered by Canonical XML 1.0 sec.2.3.
    #[must_use]
    pub fn canonicalize(&self, comments: Comments) -> Vec<u8> {
        let mut out = String::new();
        let mut rendered = Vec::new();
        self.render(&mut out, &mut rendered, comments);
        out.into_bytes()
    }

    /// Render this element into `out`. `rendered` holds the namespace
    /// declarations in effect from output ancestors, innermost last,
    /// with the empty string standing for the default prefix.
    fn render(&self, out: &mut String, rendered: &mut Vec<(String, String)>, comments: Comments) {
        let data = self.data();
        let scope_depth = rendered.len();

        // The prefixes this element visibly utilises (xml-exc-c14n
        // sec.3): its own, and those of its prefixed attributes. An
        // unprefixed attribute is in no namespace and uses no prefix.
        let mut utilised: Vec<Option<&str>> = vec![data.prefix.as_deref()];
        for attribute in &data.attributes {
            if let Some(prefix) = attribute.prefix.as_deref()
                && !utilised.contains(&Some(prefix))
            {
                utilised.push(Some(prefix));
            }
        }
        let mut declarations: Vec<(String, String)> = Vec::new();
        for prefix in utilised {
            if prefix == Some(PREFIX_XML) {
                continue;
            }
            let key = prefix.unwrap_or_default();
            let uri = self.resolve(prefix).unwrap_or_default();
            let in_effect = rendered
                .iter()
                .rev()
                .find(|(rendered_prefix, _)| rendered_prefix == key)
                .map_or("", |(_, rendered_uri)| rendered_uri.as_str());
            if uri != in_effect {
                declarations.push((key.to_owned(), uri.to_owned()));
            }
        }
        // Namespace nodes sort by local name, the default first
        // (Canonical XML 1.0 sec.2.2 document order).
        declarations.sort();

        let mut attributes: Vec<&Attribute> = data.attributes.iter().collect();
        // Attribute nodes sort by namespace URI, then local name; an
        // attribute in no namespace has the empty URI and sorts first.
        attributes.sort_by(|left, right| {
            (left.namespace.as_deref().unwrap_or_default(), &left.local)
                .cmp(&(right.namespace.as_deref().unwrap_or_default(), &right.local))
        });

        out.push('<');
        push_qualified_name(out, data.prefix.as_deref(), &data.local);
        for (prefix, uri) in &declarations {
            out.push(' ');
            out.push_str(PREFIX_XMLNS);
            if !prefix.is_empty() {
                out.push(':');
                out.push_str(prefix);
            }
            out.push_str("=\"");
            escape_attribute_into(out, uri);
            out.push('"');
        }
        for attribute in attributes {
            out.push(' ');
            push_qualified_name(out, attribute.prefix.as_deref(), &attribute.local);
            out.push_str("=\"");
            escape_attribute_into(out, &attribute.value);
            out.push('"');
        }
        out.push('>');
        rendered.extend(declarations);

        for node in &data.children {
            match node {
                Node::Element(index) => ElementRef {
                    document: self.document,
                    index: *index,
                }
                .render(out, rendered, comments),
                Node::Text(text) => escape_text_into(out, text),
                Node::Comment(text) => {
                    if comments == Comments::Retained {
                        out.push_str(COMMENT_OPEN);
                        out.push_str(text);
                        out.push_str(COMMENT_CLOSE);
                    }
                }
                Node::ProcessingInstruction { target, data } => {
                    out.push_str(PI_OPEN);
                    out.push_str(target);
                    if !data.is_empty() {
                        out.push(' ');
                        out.push_str(data);
                    }
                    out.push_str(PI_CLOSE);
                }
            }
        }

        out.push_str(END_TAG_OPEN);
        push_qualified_name(out, data.prefix.as_deref(), &data.local);
        out.push('>');
        rendered.truncate(scope_depth);
    }
}

/// Append `prefix:local`, or `local` alone.
fn push_qualified_name(out: &mut String, prefix: Option<&str>, local: &str) {
    if let Some(prefix) = prefix {
        out.push_str(prefix);
        out.push(':');
    }
    out.push_str(local);
}

/// Escape an attribute value as Canonical XML 1.0 sec.2.3 writes it:
/// `&`, `<`, `"`, TAB, LF and CR.
fn escape_attribute_into(out: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '"' => out.push_str("&quot;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

/// Escape character data as Canonical XML 1.0 sec.2.3 writes it: `&`,
/// `<`, `>` and CR.
fn escape_text_into(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => out.push_str("&#xD;"),
            other => out.push(other),
        }
    }
}

/// Whether `character` is an XML `Char` (XML 1.0 sec.2.2 production 2).
fn is_xml_char(character: char) -> bool {
    matches!(character, '\t' | '\n' | '\r')
        || (CHAR_RANGE_1_START..=CHAR_RANGE_1_END).contains(&character)
        || (CHAR_RANGE_2_START..=CHAR_RANGE_2_END).contains(&character)
        || character >= CHAR_RANGE_3_START
}

/// Whether `character` may start an `NCName` (Namespaces in XML 1.0
/// sec.3 over XML 1.0 sec.2.3 `NameStartChar`, colon excluded). Every
/// non-ASCII character is accepted; the ASCII subset is exact.
const fn is_name_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_' || !character.is_ascii()
}

/// Whether `character` may continue an `NCName`.
const fn is_name_char(character: char) -> bool {
    is_name_start(character) || character.is_ascii_digit() || matches!(character, '-' | '.')
}

/// A name as written: optional prefix and local part.
struct QualifiedName {
    /// The part before the colon.
    prefix: Option<String>,
    /// The part after it, or the whole name.
    local: String,
}

/// An attribute as written, before namespace resolution.
struct RawAttribute {
    /// The name.
    name: QualifiedName,
    /// The normalised value.
    value: String,
}

/// The parser state: the source and the position in it.
struct Parser<'a> {
    /// The whole source.
    text: &'a str,
    /// The byte offset of the next unread character.
    position: usize,
    /// The elements parsed so far.
    elements: Vec<ElementData>,
    /// The open elements, innermost last.
    open: Vec<usize>,
}

impl<'a> Parser<'a> {
    /// A parser at the start of `text`.
    const fn new(text: &'a str) -> Self {
        Self {
            text,
            position: 0,
            elements: Vec::new(),
            open: Vec::new(),
        }
    }

    /// The unread text.
    fn rest(&self) -> &'a str {
        self.text.get(self.position..).unwrap_or_default()
    }

    /// The next unread character.
    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    /// Whether the unread text starts with `token`.
    fn at(&self, token: &str) -> bool {
        self.rest().starts_with(token)
    }

    /// Consume `token` if the unread text starts with it.
    fn eat(&mut self, token: &str) -> bool {
        if self.at(token) {
            self.position = self.position.saturating_add(token.len());
            true
        } else {
            false
        }
    }

    /// Consume `token` or fail with `what`.
    fn expect(&mut self, token: &str, what: &'static str) -> Result<(), XmlError> {
        if self.eat(token) {
            Ok(())
        } else {
            Err(XmlError::Malformed(what))
        }
    }

    /// Consume one character.
    fn bump(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.position = self.position.saturating_add(character.len_utf8());
        Some(character)
    }

    /// Consume XML whitespace (XML 1.0 sec.2.3 production 3); report
    /// whether there was any.
    fn skip_whitespace(&mut self) -> bool {
        let start = self.position;
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.position = self.position.saturating_add(1);
        }
        self.position != start
    }

    /// Consume the text up to `close` and `close` itself, returning
    /// the text.
    fn until(&mut self, close: &str, what: &'static str) -> Result<&'a str, XmlError> {
        let rest = self.rest();
        let end = rest.find(close).ok_or(XmlError::Malformed(what))?;
        let body = rest.get(..end).ok_or(XmlError::Malformed(what))?;
        self.position = self
            .position
            .saturating_add(end)
            .saturating_add(close.len());
        if !body.chars().all(is_xml_char) {
            return Err(XmlError::Malformed("character outside the XML Char set"));
        }
        Ok(body)
    }

    /// The whole document: prolog, one element, trailing misc.
    fn document(mut self) -> Result<Vec<ElementData>, XmlError> {
        if self.peek() == Some(BYTE_ORDER_MARK) {
            self.bump();
        }
        if self.at(XML_DECLARATION_OPEN)
            && self
                .rest()
                .get(XML_DECLARATION_OPEN.len()..)
                .and_then(|after| after.chars().next())
                .is_some_and(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
        {
            self.xml_declaration()?;
        }
        self.misc()?;
        if self.at(DOCTYPE_OPEN) {
            return Err(XmlError::Unsupported("document type declaration"));
        }
        if self.peek() != Some('<') {
            return Err(XmlError::Malformed("no document element"));
        }
        self.content()?;
        self.misc()?;
        if self.position != self.text.len() {
            return Err(XmlError::Malformed("content after the document element"));
        }
        Ok(self.elements)
    }

    /// The XML declaration: version and an encoding, when named, of
    /// UTF-8 (XML 1.0 sec.2.8 and sec.4.3.3).
    fn xml_declaration(&mut self) -> Result<(), XmlError> {
        self.expect(XML_DECLARATION_OPEN, "XML declaration")?;
        let body = self.until(PI_CLOSE, "unterminated XML declaration")?;
        let mut declaration = Parser::new(body);
        let mut first = true;
        loop {
            let spaced = declaration.skip_whitespace();
            if declaration.position == body.len() {
                break;
            }
            if !spaced {
                return Err(XmlError::Malformed("XML declaration"));
            }
            let name = declaration.name_token()?;
            declaration.skip_whitespace();
            declaration.expect("=", "XML declaration")?;
            declaration.skip_whitespace();
            let value = declaration.quoted_literal()?;
            match name {
                "version" if first => {}
                "encoding" if !first => {
                    if !value.eq_ignore_ascii_case(ENCODING_UTF8) {
                        return Err(XmlError::Unsupported("an encoding other than UTF-8"));
                    }
                }
                "standalone" if !first => {}
                _ => return Err(XmlError::Malformed("XML declaration")),
            }
            first = false;
        }
        if first {
            return Err(XmlError::Malformed("XML declaration without a version"));
        }
        Ok(())
    }

    /// A quoted literal with no references, for the XML declaration.
    fn quoted_literal(&mut self) -> Result<&'a str, XmlError> {
        let quote = self.bump().ok_or(XmlError::Malformed("missing quote"))?;
        let close = match quote {
            '"' => "\"",
            '\'' => "'",
            _ => return Err(XmlError::Malformed("missing quote")),
        };
        self.until(close, "unterminated literal")
    }

    /// A run of name characters, colons included.
    fn name_token(&mut self) -> Result<&'a str, XmlError> {
        let start = self.position;
        match self.peek() {
            Some(character) if is_name_start(character) => {
                self.bump();
            }
            _ => return Err(XmlError::Malformed("name expected")),
        }
        while self
            .peek()
            .is_some_and(|character| is_name_char(character) || character == ':')
        {
            self.bump();
        }
        self.text
            .get(start..self.position)
            .ok_or(XmlError::Malformed("name expected"))
    }

    /// A `QName` (Namespaces in XML 1.0 sec.4): one optional prefix and
    /// a local part, both `NCName`s.
    fn qualified_name(&mut self) -> Result<QualifiedName, XmlError> {
        let token = self.name_token()?;
        let mut parts = token.split(':');
        let (Some(first), second, None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(XmlError::Malformed("name with more than one colon"));
        };
        let valid = |part: &str| part.chars().next().is_some_and(is_name_start);
        match second {
            None => Ok(QualifiedName {
                prefix: None,
                local: first.to_owned(),
            }),
            Some(local) if valid(first) && valid(local) => Ok(QualifiedName {
                prefix: Some(first.to_owned()),
                local: local.to_owned(),
            }),
            Some(_) => Err(XmlError::Malformed("empty name part")),
        }
    }

    /// Comments, processing instructions and whitespace outside the
    /// document element.
    fn misc(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_whitespace();
            if self.eat(COMMENT_OPEN) {
                self.comment_body()?;
            } else if self.at(PI_OPEN) {
                self.processing_instruction()?;
            } else {
                return Ok(());
            }
        }
    }

    /// The rest of a comment after its opening; `--` may not occur in
    /// it (XML 1.0 sec.2.5).
    fn comment_body(&mut self) -> Result<String, XmlError> {
        let body = self.until(COMMENT_CLOSE, "unterminated comment")?;
        if body.contains("--") || body.ends_with('-') {
            return Err(XmlError::Malformed("double hyphen in a comment"));
        }
        Ok(normalise_line_ends(body))
    }

    /// A processing instruction; its target may not be `xml` in any
    /// case (XML 1.0 sec.2.6).
    fn processing_instruction(&mut self) -> Result<Node, XmlError> {
        self.expect(PI_OPEN, "processing instruction")?;
        let target = self.name_token()?;
        if target.eq_ignore_ascii_case(PREFIX_XML) {
            return Err(XmlError::Malformed("misplaced XML declaration"));
        }
        if target.contains(':') {
            return Err(XmlError::Malformed(
                "colon in a processing instruction target",
            ));
        }
        let spaced = self.skip_whitespace();
        let data = self.until(PI_CLOSE, "unterminated processing instruction")?;
        if !spaced && !data.is_empty() {
            return Err(XmlError::Malformed("processing instruction target"));
        }
        Ok(Node::ProcessingInstruction {
            target: target.to_owned(),
            data: normalise_line_ends(data),
        })
    }

    /// The document element and everything inside it.
    fn content(&mut self) -> Result<(), XmlError> {
        self.start_tag()?;
        while let Some(&current) = self.open.last() {
            if self.eat(END_TAG_OPEN) {
                self.end_tag(current)?;
            } else if self.eat(COMMENT_OPEN) {
                let text = self.comment_body()?;
                self.push_node(current, Node::Comment(text));
            } else if self.eat(CDATA_OPEN) {
                let text = normalise_line_ends(self.until(CDATA_CLOSE, "unterminated CDATA")?);
                self.push_text(current, &text);
            } else if self.at(DOCTYPE_OPEN) {
                return Err(XmlError::Unsupported("document type declaration"));
            } else if self.at(PI_OPEN) {
                let node = self.processing_instruction()?;
                self.push_node(current, node);
            } else if self.at("<") {
                self.start_tag()?;
            } else {
                let text = self.character_data()?;
                self.push_text(current, &text);
            }
        }
        Ok(())
    }

    /// Character data up to the next markup.
    fn character_data(&mut self) -> Result<String, XmlError> {
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(XmlError::Malformed("unterminated element")),
                Some('<') => return Ok(out),
                Some('&') => out.push(self.reference()?),
                Some('\r') => {
                    self.bump();
                    self.eat("\n");
                    out.push('\n');
                }
                Some(_) => {
                    if self.at(CDATA_CLOSE) {
                        return Err(XmlError::Malformed("]]> in character data"));
                    }
                    let character = self.bump().ok_or(XmlError::Malformed("truncated"))?;
                    if !is_xml_char(character) {
                        return Err(XmlError::Malformed("character outside the XML Char set"));
                    }
                    out.push(character);
                }
            }
        }
    }

    /// A reference starting at `&` (XML 1.0 sec.4.1): one of the five
    /// predefined entities or a character reference.
    fn reference(&mut self) -> Result<char, XmlError> {
        self.expect("&", "reference")?;
        let body = self.until(";", "unterminated reference")?;
        let resolved = match body {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => {
                if let Some(digits) = body.strip_prefix(CHAR_REF_HEX) {
                    character_reference(digits, RADIX_HEX)
                } else if let Some(digits) = body.strip_prefix(CHAR_REF_DECIMAL) {
                    character_reference(digits, RADIX_DECIMAL)
                } else {
                    return Err(XmlError::Unsupported("entity reference"));
                }
            }
        };
        resolved.ok_or(XmlError::Malformed("character reference"))
    }

    /// Append `node` to the children of the element at `parent`.
    fn push_node(&mut self, parent: usize, node: Node) {
        if let Some(element) = self.elements.get_mut(parent) {
            element.children.push(node);
        }
    }

    /// Append character data to `parent`, merging with a preceding
    /// text child.
    fn push_text(&mut self, parent: usize, text: &str) {
        if text.is_empty() {
            return;
        }
        if let Some(element) = self.elements.get_mut(parent) {
            if let Some(Node::Text(previous)) = element.children.last_mut() {
                previous.push_str(text);
            } else {
                element.children.push(Node::Text(text.to_owned()));
            }
        }
    }

    /// A start tag or empty-element tag at `<`.
    fn start_tag(&mut self) -> Result<(), XmlError> {
        if self.open.len() >= MAX_DEPTH {
            return Err(XmlError::TooDeep);
        }
        let start = self.position;
        self.expect("<", "start tag")?;
        let name = self.qualified_name()?;
        let mut raw = Vec::new();
        let empty = loop {
            let spaced = self.skip_whitespace();
            if self.eat(EMPTY_TAG_CLOSE) {
                break true;
            }
            if self.eat(">") {
                break false;
            }
            if !spaced {
                return Err(XmlError::Malformed(
                    "attributes must be separated by whitespace",
                ));
            }
            let attribute_name = self.qualified_name()?;
            self.skip_whitespace();
            self.expect("=", "attribute without a value")?;
            self.skip_whitespace();
            let value = self.attribute_value()?;
            raw.push(RawAttribute {
                name: attribute_name,
                value,
            });
        };

        let index = self.elements.len();
        let parent = self.open.last().copied();
        let mut declarations = Vec::new();
        let mut plain = Vec::new();
        for attribute in raw {
            match (
                attribute.name.prefix.as_deref(),
                attribute.name.local.as_str(),
            ) {
                (None, PREFIX_XMLNS) => {
                    if attribute.value == NAMESPACE_XML || attribute.value == NAMESPACE_XMLNS {
                        return Err(XmlError::Malformed("reserved namespace as the default"));
                    }
                    declarations.push(Declaration {
                        prefix: None,
                        uri: attribute.value,
                    });
                }
                (Some(PREFIX_XMLNS), PREFIX_XML) => {
                    if attribute.value != NAMESPACE_XML {
                        return Err(XmlError::Malformed("xml prefix rebound"));
                    }
                }
                (Some(PREFIX_XMLNS), PREFIX_XMLNS) => {
                    return Err(XmlError::Malformed("xmlns prefix declared"));
                }
                (Some(PREFIX_XMLNS), prefix) => {
                    if attribute.value.is_empty() {
                        return Err(XmlError::Malformed("prefix undeclared"));
                    }
                    if attribute.value == NAMESPACE_XML || attribute.value == NAMESPACE_XMLNS {
                        return Err(XmlError::Malformed("reserved namespace bound to a prefix"));
                    }
                    declarations.push(Declaration {
                        prefix: Some(prefix.to_owned()),
                        uri: attribute.value,
                    });
                }
                _ => plain.push(attribute),
            }
        }
        for (position, declaration) in declarations.iter().enumerate() {
            if declarations
                .iter()
                .skip(position.saturating_add(1))
                .any(|other| other.prefix == declaration.prefix)
            {
                return Err(XmlError::Malformed("duplicate namespace declaration"));
            }
        }
        if name.prefix.as_deref() == Some(PREFIX_XMLNS) {
            return Err(XmlError::Malformed("element in the xmlns namespace"));
        }

        self.elements.push(ElementData {
            prefix: name.prefix,
            local: name.local,
            namespace: None,
            attributes: Vec::new(),
            declarations,
            children: Vec::new(),
            parent,
            span: start..start,
        });
        let resolver = ResolveAt {
            elements: &self.elements,
            index,
        };
        let element_prefix = self
            .elements
            .get(index)
            .and_then(|element| element.prefix.clone());
        let namespace = match element_prefix.as_deref() {
            None => resolver.resolve(None).map(str::to_owned),
            Some(prefix) => Some(
                resolver
                    .resolve(Some(prefix))
                    .ok_or(XmlError::Malformed("undeclared element prefix"))?
                    .to_owned(),
            ),
        };
        let mut attributes: Vec<Attribute> = Vec::with_capacity(plain.len());
        for attribute in plain {
            let attribute_namespace = match attribute.name.prefix.as_deref() {
                None => None,
                Some(prefix) => Some(
                    resolver
                        .resolve(Some(prefix))
                        .ok_or(XmlError::Malformed("undeclared attribute prefix"))?
                        .to_owned(),
                ),
            };
            if attributes.iter().any(|existing| {
                existing.local == attribute.name.local && existing.namespace == attribute_namespace
            }) {
                return Err(XmlError::Malformed("duplicate attribute"));
            }
            attributes.push(Attribute {
                prefix: attribute.name.prefix,
                local: attribute.name.local,
                namespace: attribute_namespace,
                value: attribute.value,
            });
        }
        if let Some(element) = self.elements.get_mut(index) {
            element.namespace = namespace;
            element.attributes = attributes;
            element.span = start..self.position;
        }
        if let Some(parent) = parent {
            self.push_node(parent, Node::Element(index));
        }
        if !empty {
            self.open.push(index);
        }
        Ok(())
    }

    /// An end tag after its `</`, which must name the open element.
    fn end_tag(&mut self, current: usize) -> Result<(), XmlError> {
        let name = self.qualified_name()?;
        self.skip_whitespace();
        self.expect(">", "unterminated end tag")?;
        let end = self.position;
        let element = self
            .elements
            .get_mut(current)
            .ok_or(XmlError::Malformed("end tag without a start tag"))?;
        if element.prefix != name.prefix || element.local != name.local {
            return Err(XmlError::Malformed("end tag does not match the start tag"));
        }
        element.span.end = end;
        self.open.pop();
        Ok(())
    }

    /// A quoted attribute value, normalised as XML 1.0 sec.3.3.3 does
    /// for `CDATA`: each literal whitespace character becomes a space,
    /// a CR LF pair one space, and references are resolved without
    /// normalisation.
    fn attribute_value(&mut self) -> Result<String, XmlError> {
        let quote = self
            .bump()
            .ok_or(XmlError::Malformed("attribute value expected"))?;
        if quote != '"' && quote != '\'' {
            return Err(XmlError::Malformed("attribute value must be quoted"));
        }
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err(XmlError::Malformed("unterminated attribute value")),
                Some(character) if character == quote => {
                    self.bump();
                    return Ok(out);
                }
                Some('<') => return Err(XmlError::Malformed("< in an attribute value")),
                Some('&') => out.push(self.reference()?),
                Some('\r') => {
                    self.bump();
                    self.eat("\n");
                    out.push(' ');
                }
                Some('\n' | '\t') => {
                    self.bump();
                    out.push(' ');
                }
                Some(_) => {
                    let character = self.bump().ok_or(XmlError::Malformed("truncated"))?;
                    if !is_xml_char(character) {
                        return Err(XmlError::Malformed("character outside the XML Char set"));
                    }
                    out.push(character);
                }
            }
        }
    }
}

/// Namespace resolution over the elements parsed so far.
struct ResolveAt<'a> {
    /// The element arena.
    elements: &'a [ElementData],
    /// The element resolution starts at.
    index: usize,
}

impl<'a> ResolveAt<'a> {
    /// What `prefix` resolves to at the element: its declarations, then
    /// its ancestors'.
    fn resolve(&self, prefix: Option<&str>) -> Option<&'a str> {
        if prefix == Some(PREFIX_XML) {
            return Some(NAMESPACE_XML);
        }
        let mut current = Some(self.index);
        while let Some(index) = current {
            let element = self.elements.get(index)?;
            if let Some(declaration) = element
                .declarations
                .iter()
                .find(|declaration| declaration.prefix.as_deref() == prefix)
            {
                return if declaration.uri.is_empty() {
                    None
                } else {
                    Some(declaration.uri.as_str())
                };
            }
            current = element.parent;
        }
        None
    }
}

/// Resolve the digits of a character reference to a `Char`.
fn character_reference(digits: &str, radix: u32) -> Option<char> {
    if digits.is_empty() || !digits.chars().all(|digit| digit.is_digit(radix)) {
        return None;
    }
    u32::from_str_radix(digits, radix)
        .ok()
        .and_then(char::from_u32)
        .filter(|character| is_xml_char(*character))
}

/// End-of-line handling (XML 1.0 sec.2.11): CR LF and a lone CR both
/// become LF.
fn normalise_line_ends(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::{Comments, XmlDocument, XmlError};

    fn parse(text: &str) -> XmlDocument {
        XmlDocument::parse(text.as_bytes().to_vec()).expect("parses")
    }

    fn canonical(text: &str) -> String {
        String::from_utf8(parse(text).root().canonicalize(Comments::Omitted)).expect("utf-8")
    }

    #[test]
    fn prefixes_resolve_through_declarations_in_scope() {
        let document = parse(r#"<a:x xmlns:a="urn:a" xmlns="urn:d"><y a:k="v"/><a:z/></a:x>"#);
        let root = document.root();
        assert!(root.is("urn:a", "x"));
        let children: Vec<_> = root.children().collect();
        assert_eq!(children.len(), 2);
        assert!(children[0].is("urn:d", "y"));
        assert!(children[1].is("urn:a", "z"));
        assert_eq!(
            children[0].attribute("k"),
            None,
            "a prefixed attribute is namespaced"
        );
    }

    #[test]
    fn spans_cover_the_element_exactly() {
        let text = r#"<?xml version="1.0"?><r><c a="1">t</c><e/></r>"#;
        let document = parse(text);
        let elements: Vec<_> = document.elements().collect();
        let slice = |index: usize| &text[elements[index].span()];
        assert_eq!(slice(0), r#"<r><c a="1">t</c><e/></r>"#);
        assert_eq!(slice(1), r#"<c a="1">t</c>"#);
        assert_eq!(slice(2), "<e/>");
    }

    #[test]
    fn references_comments_and_cdata_are_resolved() {
        let document = parse("<r>&amp;&lt;&#x41;&#66;<!-- c --><![CDATA[<raw>]]>\r\n</r>");
        assert_eq!(document.root().text(), "&<AB<raw>\n");
    }

    #[test]
    fn exotic_constructs_are_refused() {
        let refuse = |text: &str| XmlDocument::parse(text.as_bytes().to_vec()).err();
        assert_eq!(
            refuse("<!DOCTYPE r><r/>"),
            Some(XmlError::Unsupported("document type declaration"))
        );
        assert_eq!(
            refuse("<r>&custom;</r>"),
            Some(XmlError::Unsupported("entity reference"))
        );
        assert!(matches!(refuse("<p:r/>"), Some(XmlError::Malformed(_))));
        assert!(matches!(
            refuse("<r a='1' a='2'/>"),
            Some(XmlError::Malformed(_))
        ));
        assert!(matches!(refuse("<r></s>"), Some(XmlError::Malformed(_))));
        assert!(matches!(refuse("<r/><s/>"), Some(XmlError::Malformed(_))));
        assert!(matches!(
            refuse(r#"<?xml version="1.0" encoding="ISO-8859-1"?><r/>"#),
            Some(XmlError::Unsupported(_))
        ));
    }

    #[test]
    fn nesting_is_bounded() {
        let depth = super::MAX_DEPTH.saturating_add(1);
        let text = format!("{}{}", "<a>".repeat(depth), "</a>".repeat(depth));
        assert_eq!(
            XmlDocument::parse(text.into_bytes()).err(),
            Some(XmlError::TooDeep)
        );
    }

    /// Canonical XML 1.0 sec.3.2 and sec.3.3 in miniature: empty
    /// elements get end tags, attributes are sorted and requoted,
    /// values are normalised, and only the escapes c14n names remain.
    #[test]
    fn canonical_form_follows_canonical_xml_section_2_3() {
        assert_eq!(
            canonical("<r b='2' a=\"x&#9;y\n z\" c='&apos;&gt;'><e/>a&gt;b&#13;</r>"),
            "<r a=\"x&#x9;y  z\" b=\"2\" c=\"'>\"><e></e>a&gt;b&#xD;</r>"
        );
    }

    /// Namespaced attributes sort after unqualified ones, by URI then
    /// local name, whatever their prefixes.
    #[test]
    fn attributes_sort_by_namespace_uri_then_local_name() {
        assert_eq!(
            canonical(r#"<r xmlns:z="urn:a" xmlns:a="urn:b" a:x="1" z:y="2" b="3"/>"#),
            r#"<r xmlns:a="urn:b" xmlns:z="urn:a" b="3" z:y="2" a:x="1"></r>"#
        );
    }

    /// The exclusive rule: a declaration appears where the prefix is
    /// first visibly used, an unused one never, and one already in
    /// effect is not repeated.
    #[test]
    fn exclusive_canonicalisation_renders_declarations_where_used() {
        let document = parse(
            r#"<o xmlns:u="urn:unused" xmlns:a="urn:a" xmlns="urn:d"><a:x><a:y/><z/></a:x></o>"#,
        );
        let inner = document.root().children().next().expect("child");
        let bytes = inner.canonicalize(Comments::Omitted);
        assert_eq!(
            String::from_utf8(bytes).expect("utf-8"),
            r#"<a:x xmlns:a="urn:a"><a:y></a:y><z xmlns="urn:d"></z></a:x>"#
        );
        assert_eq!(
            canonical(r#"<r xmlns="urn:d"><s xmlns=""/></r>"#),
            r#"<r xmlns="urn:d"><s xmlns=""></s></r>"#
        );
    }

    #[test]
    fn comments_are_kept_only_when_asked() {
        let document = parse("<r><!--c--><?p d?></r>");
        let with = document.root().canonicalize(Comments::Retained);
        let without = document.root().canonicalize(Comments::Omitted);
        assert_eq!(
            String::from_utf8(with).expect("utf-8"),
            "<r><!--c--><?p d?></r>"
        );
        assert_eq!(String::from_utf8(without).expect("utf-8"), "<r><?p d?></r>");
    }

    #[test]
    fn descendants_stay_inside_the_subtree() {
        let document = parse("<r><a><b/></a><c/></r>");
        let first = document.root().children().next().expect("a");
        let names: Vec<_> = first
            .descendants()
            .map(|element| element.local_name())
            .collect();
        assert_eq!(names, ["a", "b"]);
    }
}
