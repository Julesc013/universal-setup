# Selected NTFS candidate package

`tools/usk_selected_candidate_package.py` combines a finalized Windows x64
product bundle and four actual native executables into one directory. It keeps
the verified inspect-only prefab under `inspect/` and puts the ordinary,
gate-free restricted service, service control and request client under
`publisher/`. `setup-package.manifest.json` binds every emitted file by size
and SHA-256. The builder reopens the complete package and refuses a fault-test
service executable, unexpected members or changed bytes.

```text
python tools/usk_selected_candidate_package.py build \
  --bundle <selected>/product.bundle.json \
  --machine <build>/usk_machine.exe \
  --service <build>/usk_publisher_lab_service.exe \
  --control <build>/usk_publisher_service_control.exe \
  --client <build>/usk_publisher_client.exe \
  --output-dir <existing-empty-directory>
python tools/usk_selected_candidate_package.py inspect --path <package-directory>
```

The hosted registered-service probe builds this package from an authored
selected bundle and the actual Windows build, then plans and installs from its
packaged payload and executables on a new disposable NTFS VHD. It removes the
packaged payload and other authoring/source inputs before source-free reentry.

This is an **unsigned candidate package** for the selected laboratory profile.
It does not provision an ordinary customer machine, certify binary imports,
grant general target authority, or qualify the 1.1 release. The VHD device ACL
helper and fault-test service stay outside the package. The public strict
publisher gate remains closed.
