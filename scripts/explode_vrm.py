#!/usr/bin/env python3
"""Explode a VRM (glTF binary) into a tree of USDA stages.

Every top-level glTF asset (scene, node, mesh, material, texture,
image, buffer) becomes its own .usda file, plus extracted binary
assets for images. A root.usda references the top-level counts.

Recursion is stage-shaped: nodes reference child node stages, meshes
reference material stages, materials reference texture stages,
textures reference image binaries. What sqlar-cas ingests is a
directory of small files rather than one monolithic blob, so cross-
avatar chunk dedup applies at every level of the tree.
"""

import argparse
import json
import pathlib
import struct
import sys


def parse_glb(data):
    if data[:4] != b"glTF":
        raise ValueError("not a glTF binary (missing 'glTF' magic)")
    version, total_len = struct.unpack("<II", data[4:12])
    if version != 2:
        raise ValueError(f"unsupported glTF version {version}")
    pos = 12
    json_bytes = None
    bin_bytes = b""
    while pos < len(data):
        chunk_len, chunk_type = struct.unpack("<II", data[pos : pos + 8])
        pos += 8
        chunk_data = data[pos : pos + chunk_len]
        pos += chunk_len
        if chunk_type == 0x4E4F534A:
            json_bytes = chunk_data
        elif chunk_type == 0x004E4942:
            bin_bytes = chunk_data
    if json_bytes is None:
        raise ValueError("no JSON chunk in glb")
    return json.loads(json_bytes), bin_bytes


def usda_prim(prim_type, name, attrs, header="#usda 1.0\n"):
    out = [header, f'(defaultPrim = "{name}")\n\n']
    out.append(f'def {prim_type} "{name}"\n{{\n')
    for k, v in attrs.items():
        out.append(f"    {k} = {v}\n")
    out.append("}\n")
    return "".join(out)


def q(s):
    return '"' + str(s).replace('"', '\\"') + '"'


def write_stage(root, rel, prim_type, name, attrs):
    p = pathlib.Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(usda_prim(prim_type, name, attrs))
    return rel


def explode(vrm_path, out_dir):
    data = pathlib.Path(vrm_path).read_bytes()
    gltf, bin_data = parse_glb(data)
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    scenes = gltf.get("scenes", [])
    nodes = gltf.get("nodes", [])
    meshes = gltf.get("meshes", [])
    materials = gltf.get("materials", [])
    textures = gltf.get("textures", [])
    images = gltf.get("images", [])
    buffers = gltf.get("buffers", [])
    buffer_views = gltf.get("bufferViews", [])
    accessors = gltf.get("accessors", [])

    for i, img in enumerate(images):
        if "bufferView" not in img:
            continue
        bv = buffer_views[img["bufferView"]]
        off, ln = bv.get("byteOffset", 0), bv["byteLength"]
        img_bytes = bin_data[off : off + ln]
        mime = img.get("mimeType", "application/octet-stream")
        ext = "png" if "png" in mime else "jpg" if "jpeg" in mime else "bin"
        (out / "images").mkdir(parents=True, exist_ok=True)
        (out / "images" / f"image_{i}.{ext}").write_bytes(img_bytes)
        write_stage(
            out, f"images/image_{i}.usda", "Image", f"Image_{i}",
            {
                "string mimeType": q(mime),
                "asset uri": f"@image_{i}.{ext}@",
                "int sizeBytes": str(len(img_bytes)),
            },
        )

    for i, tex in enumerate(textures):
        src = tex.get("source")
        write_stage(
            out, f"textures/texture_{i}.usda", "Texture", f"Tex_{i}",
            {
                "int sourceImage": str(src) if src is not None else "-1",
                "asset image": f"@../images/image_{src}.usda@"
                if src is not None else '""',
            },
        )

    for i, mat in enumerate(materials):
        pbr = mat.get("pbrMetallicRoughness", {})
        base_tex = pbr.get("baseColorTexture", {}).get("index", -1)
        write_stage(
            out, f"materials/material_{i}.usda", "Material", f"Mat_{i}",
            {
                "string name": q(mat.get("name", f"mat_{i}")),
                "int baseColorTextureIndex": str(base_tex),
                "asset baseColorTexture": f"@../textures/texture_{base_tex}.usda@"
                if base_tex >= 0 else '""',
            },
        )

    for i, mesh in enumerate(meshes):
        prims = mesh.get("primitives", [])
        mat_refs = ", ".join(
            f'@../materials/material_{p["material"]}.usda@'
            for p in prims if "material" in p
        )
        write_stage(
            out, f"meshes/mesh_{i}.usda", "Mesh", f"Mesh_{i}",
            {
                "string name": q(mesh.get("name", f"mesh_{i}")),
                "int primitiveCount": str(len(prims)),
                "asset[] materials": f"[{mat_refs}]" if mat_refs else "[]",
            },
        )

    for i, node in enumerate(nodes):
        children = node.get("children", [])
        child_refs = ", ".join(
            f"@../nodes/node_{c}.usda@" for c in children
        )
        mesh_idx = node.get("mesh", -1)
        write_stage(
            out, f"nodes/node_{i}.usda", "Xform", f"Node_{i}",
            {
                "string name": q(node.get("name", f"node_{i}")),
                "asset[] children": f"[{child_refs}]" if child_refs else "[]",
                "int meshIndex": str(mesh_idx),
                "asset mesh": f"@../meshes/mesh_{mesh_idx}.usda@"
                if mesh_idx >= 0 else '""',
            },
        )

    for i, scene in enumerate(scenes):
        roots = scene.get("nodes", [])
        root_refs = ", ".join(f"@../nodes/node_{r}.usda@" for r in roots)
        write_stage(
            out, f"scenes/scene_{i}.usda", "Scope", f"Scene_{i}",
            {
                "string name": q(scene.get("name", f"scene_{i}")),
                "asset[] rootNodes": f"[{root_refs}]" if root_refs else "[]",
            },
        )

    write_stage(
        out, "root.usda", "Xform", "Avatar",
        {
            "int sceneCount": str(len(scenes)),
            "int nodeCount": str(len(nodes)),
            "int meshCount": str(len(meshes)),
            "int materialCount": str(len(materials)),
            "int textureCount": str(len(textures)),
            "int imageCount": str(len(images)),
            "int bufferByteLength": str(len(bin_data)),
            "asset defaultScene": "@scenes/scene_0.usda@"
            if scenes else '""',
        },
    )

    return {
        "scenes": len(scenes),
        "nodes": len(nodes),
        "meshes": len(meshes),
        "materials": len(materials),
        "textures": len(textures),
        "images": len(images),
        "bin_bytes": len(bin_data),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--vrm",
        default="/tmp/vrm-sample/Constraint_Twist_Sample/Art/VRM1/"
                "VRM1_Constraint_Twist_Sample_01.vrm",
    )
    ap.add_argument("--out", default="testdata/exploded/vrm")
    args = ap.parse_args()
    stats = explode(args.vrm, args.out)
    print(f"exploded {args.vrm} -> {args.out}")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"  total stage files: {sum(1 for _ in pathlib.Path(args.out).rglob('*.usda'))}")


if __name__ == "__main__":
    main()
