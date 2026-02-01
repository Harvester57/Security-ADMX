# ADMX/ADML Development Style Guide

## 1. File Structure and Naming Conventions

* **File Pairing:** Every Policy Definition (`.admx`) file must have a corresponding Policy Definition Resource (`.adml`) file for each supported language.
* **Naming:** The `fileName` attribute must match the physical filename without the extension.
* **Directory Layout:**
    * `PolicyDefinitions\` -> Contains `.admx` files.
    * `PolicyDefinitions\en-US\` -> Contains `.adml` files for English language.
    * `PolicyDefinitions\fr-FR\` -> Contains `.adml` files for French language.

## 2. XML Prolog and Root Definitions

All files must utilize standard XML 1.0 encoding.

### ADMX Files (Policy Definitions)
* **Root Element:** Must be `<policyDefinitions>`.
* **Required Attributes:**
    * `revision`: Format `x.y` (e.g., `1.0`).
    * `schemaVersion`: Format `x.y` (e.g., `1.0`).
* **Namespace Declaration:**
    * Default `xmlns`: `http://www.microsoft.com/GroupPolicy/PolicyDefinitions`
    * XSD `xmlns:xs`: `http://www.w3.org/2001/XMLSchema`
* **Structure Sequence:**
    1.  `policyNamespaces` (Required)
    2.  `supersededAdm` (Optional)
    3.  `annotation` (Optional)
    4.  `resources` (Required)
    5.  `supportedOn` (Optional)
    6.  `categories` (Optional)
    7.  `policies` (Optional)

### ADML Files (Localization Resources)
* **Root Element:** Must be `<policyDefinitionResources>`.
* **Required Attributes:**
    * `revision`: Format `x.y`
    * `schemaVersion`: Format `x.y`
* **Structure Sequence:**
    1.  `displayName`
    2.  `description`
    3.  `annotation` (Optional)
    4.  `resources` (Contains `stringTable` and `presentationTable`)

## 3. Data Type Constraints

Adhere strictly to the defined simple types in the schema.

* **GUIDs:** Must follow the registry format `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
* **Item Names:** Alphanumeric and underscores only `(\p{L}|\p{N}|_)+`. No spaces or hyphens allowed in ID attributes for policies or categories.
* **Registry Keys:** Must be valid registry paths without hive references (e.g., `Software\Policies\MyApp`).
* **Version Strings:** Must match the regex `[0-9]{1,4}\.[0-9]{1,5}` (e.g., `1.2`, `10.55`).

## 4. Localization and Referencing Syntax

### String References (ADMX)
* **Syntax:** Use `$(string.id)` to reference localized strings.
* **Definition (ADML):** Defined in `<stringTable>` as `<string id="id">Value</string>`.
* **Constraint:** The ID used in the ADMX reference must exist in the ADML `stringTable`.

### Presentation References (ADMX)
* **Syntax:** Use `$(presentation.id)` to reference UI presentation definitions.
* **Definition (ADML):** Defined in `<presentationTable>` as `<presentation id="id">...</presentation>`.

### Namespace Association
* **Prefixing:** The `policyNamespaces` element must define a `prefix` and `namespace` URI (target).
* **Usage:** Used to reference definitions between different ADMX files.

## 5. Code Style and Formatting

* **Indentation:** Use 2 spaces for XML indentation.
* **Attributes:** Quote all attribute values.
* **Comments:** Use `` for annotations.
* **Prohibited Characters:** Do not use em dashes (—); use colons (:), semicolons (;), or hyphens (-).

## 6. Example Templates

### ADMX Skeleton
```xml
<?xml version="1.0" encoding="utf-8"?>
<policyDefinitions revision="1.0" schemaVersion="1.0" 
    xmlns="[http://www.microsoft.com/GroupPolicy/PolicyDefinitions](http://www.microsoft.com/GroupPolicy/PolicyDefinitions)">
  <policyNamespaces>
    <target prefix="myApp" namespace="MyCompany.Policies.MyApp" />
  </policyNamespaces>
  <resources minRequiredRevision="1.0" />
  <categories>
    <category name="Cat_MyApp" displayName="$(string.Cat_MyApp)">
      <parentCategory ref="windows:Custom" />
    </category>
  </categories>
  <policies>
    </policies>
</policyDefinitions>