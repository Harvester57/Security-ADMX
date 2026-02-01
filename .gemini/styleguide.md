# ADMX/ADML Development Style Guide

## 1. File Structure and Naming Conventions

* [cite_start]**File Pairing:** Every Policy Definition (`.admx`) file must have a corresponding Policy Definition Resource (`.adml`) file for each supported language[cite: 10].
* [cite_start]**Naming:** The `fileName` attribute must match the physical filename without the extension[cite: 19].
* **Directory Layout:**
    * `PolicyDefinitions\` -> Contains `.admx` files.
    * `PolicyDefinitions\en-US\` -> Contains `.adml` files (replace `en-US` with specific culture).

## 2. XML Prolog and Root Definitions

All files must utilize standard XML 1.0 encoding.

### ADMX Files (Policy Definitions)
* [cite_start]**Root Element:** Must be `<policyDefinitions>`[cite: 10].
* **Required Attributes:**
    * [cite_start]`revision`: Format `x.y` (e.g., `1.0`)[cite: 7, 12].
    * [cite_start]`schemaVersion`: Format `x.y` (e.g., `1.0`)[cite: 7, 12].
* **Namespace Declaration:**
    * [cite_start]Default `xmlns`: `http://www.microsoft.com/GroupPolicy/PolicyDefinitions`[cite: 1].
    * [cite_start]XSD `xmlns:xs`: `http://www.w3.org/2001/XMLSchema`[cite: 1].
* **Structure Sequence:**
    1.  `policyNamespaces` (Required)
    2.  `supersededAdm` (Optional)
    3.  `annotation` (Optional)
    4.  `resources` (Required)
    5.  `supportedOn` (Optional)
    6.  `categories` (Optional)
    7.  [cite_start]`policies` (Optional)[cite: 6, 7].

### ADML Files (Localization Resources)
* [cite_start]**Root Element:** Must be `<policyDefinitionResources>`[cite: 10].
* **Required Attributes:**
    * [cite_start]`revision`: Format `x.y`[cite: 9, 12].
    * [cite_start]`schemaVersion`: Format `x.y`[cite: 9, 12].
* **Structure Sequence:**
    1.  `displayName`
    2.  `description`
    3.  `annotation` (Optional)
    4.  [cite_start]`resources` (Contains `stringTable` and `presentationTable`)[cite: 9, 2, 3].

## 3. Data Type Constraints

Adhere strictly to the defined simple types in the schema.

* [cite_start]**GUIDs:** Must follow the registry format `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`[cite: 11].
* **Item Names:** Alphanumeric and underscores only `(\p{L}|\p{N}|_)+`. [cite_start]No spaces or hyphens allowed in ID attributes for policies or categories[cite: 15].
* [cite_start]**Registry Keys:** Must be valid registry paths without hive references (e.g., `Software\Policies\MyApp`)[cite: 17].
* [cite_start]**Version Strings:** Must match the regex `[0-9]{1,4}\.[0-9]{1,5}` (e.g., `1.2`, `10.55`)[cite: 12].

## 4. Localization and Referencing Syntax

### String References (ADMX)
* [cite_start]**Syntax:** Use `$(string.id)` to reference localized strings[cite: 12].
* [cite_start]**Definition (ADML):** Defined in `<stringTable>` as `<string id="id">Value</string>`[cite: 2].
* **Constraint:** The ID used in the ADMX reference must exist in the ADML `stringTable`.

### Presentation References (ADMX)
* [cite_start]**Syntax:** Use `$(presentation.id)` to reference UI presentation definitions[cite: 13].
* [cite_start]**Definition (ADML):** Defined in `<presentationTable>` as `<presentation id="id">...</presentation>`[cite: 3].

### Namespace Association
* [cite_start]**Prefixing:** The `policyNamespaces` element must define a `prefix` and `namespace` URI (target)[cite: 5].
* **Usage:** Used to reference definitions between different ADMX files.

## 5. Code Style and formatting

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