# MaxPayout Core Business Logic Suite

Welcome to the **MaxPayout** suite of standalone, pure business-logic libraries. 

This workspace contains four decoupled, high-performance Rust crates migrated from the Royal Flush Network (RFN). By design, these libraries contain **zero database dependencies**, **zero asynchronous framework coupling**, and **zero direct network operations**. 

These libraries run fully synchronously and rely on the **Synchronous Outbox Pattern** to output state transitions as structured domain events.

---

## Workspace Crate Catalog

The workspace consists of the following 4 individual crates:

| Crate | Purpose | Location |
| :--- | :--- | :--- |
| **[`flushline`](file:///Users/uriah/Code/maxpayout/flushline)** | 5-tier card progression engine (Ten -> Jack -> Queen -> King -> Ace). | `./flushline` |
| **[`matrix`](file:///Users/uriah/Code/maxpayout/matrix)** | 2x3 forced-matrix referral tree (7-slot) cycling engine. | `./matrix` |
| **[`sponsor_allocator`](file:///Users/uriah/Code/maxpayout/sponsor_allocator)** | Sponsor pool management and allocation strategies. | `./sponsor_allocator` |
| **[`potbonus`](file:///Users/uriah/Code/maxpayout/potbonus)** | Weekly 75-25 pot bonus orchestrator with dual qualification and user-level aggregation. | `./potbonus` |

---

## WebAssembly (WASM) & WASI Support

All four crates are fully compatible with WebAssembly **out of the box**. They support compilation for both browser environments (Leptos frontend clients) and server-side WASM sandboxes (such as **Leptos Spin** or **Leptos Wasmtime**).

### 1. Browser-Side WebAssembly (`wasm32-unknown-unknown`)

When compiling Rust for standard browser targets, there is no direct access to native operating system entropy providers (like `/dev/urandom`). 

* **The Problem**: Generating secure `v7` UUIDs using the `uuid` crate requires a source of randomness, which blocks normal compilation on browser WASM targets.
* **The Solution**: All MaxPayout crates pre-configure the `uuid` crate with the `"js"` feature enabled:
  ```toml
  uuid = { version = "1.0", features = ["v7", "serde", "js"] }
  ```
  This automatically instructs the compiled WebAssembly module to request secure entropy from browser-native JavaScript APIs (`window.crypto.getRandomValues`).

#### Setup Requirements for Browser Compile:
1. Ensure the Rust WebAssembly target is installed on your system:
   ```bash
   rustup target add wasm32-unknown-unknown
   ```
2. Build or check compilation for standard browsers:
   ```bash
   cargo check --target wasm32-unknown-unknown
   ```

---

### 2. Server-Side WASM / WASI (`wasm32-wasip1` / `wasm32-wasi`)

If you are deploying these crates to **Leptos Spin** or **Leptos Wasmtime**, they run on top of WASI (WebAssembly System Interface).

* **Out-of-the-Box Resolution**: WASI provides a standardized system-call interface (`random_get`) to request secure entropy from the host system.
* **No Configuration Needed**: The `getrandom` and `uuid` crates natively support WASI. Thus, compiling for server-side runtimes like Wasmtime or Spin resolves randomness automatically.

#### Setup Requirements for WASI Compile:
1. Ensure the WASI target is installed on your rust toolchain:
   ```bash
   rustup target add wasm32-wasip1
   ```
2. Compile and check for WASI targets:
   ```bash
   cargo check --target wasm32-wasip1
   ```

---

### 3. Integrating with Leptos Spin / Wasmtime

Because Leptos compiles single-source files into both client-side modules (executing in the browser via `wasm32-unknown-unknown`) and server-side modules (executing in Spin/Wasmtime via `wasm32-wasip1` or native), our crates are specifically configured to accommodate **both targets simultaneously**.

To use them in your Leptos application:

1. **Add Crate Dependencies**: Add relative path-based or git-based references in your Leptos `Cargo.toml`:
   ```toml
   [dependencies]
   flushline = { path = "../maxpayout/flushline" }
   matrix = { path = "../maxpayout/matrix" }
   sponsor_allocator = { path = "../maxpayout/sponsor_allocator" }
   potbonus = { path = "../maxpayout/potbonus" }
   ```
2. **Build the Leptos App**: Run your standard Leptos build pipeline (e.g. via `cargo-leptos`):
   ```bash
   cargo leptos build --release
   ```
   The build pipeline will seamlessly compile the UI portions under `wasm32-unknown-unknown` (using the JS randomness bindings) and server-side SSR components under your host/WASI runtime (using the system calls) without any compilation conflicts.

---

## Architectural Guidelines & Best Practices

To maintain the decoupling achieved in this suite, please adhere to these design guidelines when extending the code:
1. **Synchronous Execution**: Always write business rules, calculations, and state changes synchronously. Never spawn futures, database queries, or network requests inside the domain libraries.
2. **Standard Outbox Pattern**: Instead of side-effecting, construct strongly typed domain events locally, push them onto internal outbox queues, and return them.
3. **No Cross-Coupling**: Maintain strict isolation. Sibling crates do not compile-depend on each other. If one crate needs to ingest events from another (e.g., `sponsor_allocator` ingests `FlushlineGraduated` and `MatrixCycled`), it declares local ingestion event structures that deserialization can map to.
