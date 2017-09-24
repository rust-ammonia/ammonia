# Unreleased

* Breaking change: The `Ammonia` struct is now called `Builder` and uses that pattern for better forward compatibility
* Breaking change: The `Builder::clean()` method now returns a `Document` struct instead of a `String`
* Breaking change: `keep_cleaned_elements` is changed from being an off-by-default option to the only supported behavior
* Breaking change: Using a tag with `allowed_classes` means that the class attribute is banned from `tag_attributes` (it used to be required)
* Added support for reading the input from a stream

# 0.7.0

* Add `allowed_classes`, allowing the user to set only specific items that can go in the class attribute

# 0.6.1

* Fix a bug in the traversal code

# 0.6.0

* Resolve relative URLs with a given base (off by default, you need to specify that base URL)
* Add `rel="noreferrer noopener"` to links, as a security measure
* Avoid closing void tags, such as turning `<br>` into `<br></br>`
* Bump the html5ever version
* Switch to using docs.rs to host docs

# 0.5.0

* Bump html5ever to 0.18 (this updates serde from 0.9 to 1.0)

# 0.4.0

* Upgrade to html5ever 0.17

# 0.3.0

* Add an option to keep elements that had attributes removed

# 0.2.0

* Removed the strip option. Not a security problem, but it was wrong and looked stupid. I'm not going to reintroduce this until html5ever allows me to preserve the original text enough to have non-stripped tags come out exactly like they go in.
* Treat the data attribute of object as a URL. In non-default configurations, this could have been a leak.
* Update to the newest html5ever.
