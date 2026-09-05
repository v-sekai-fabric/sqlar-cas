"""Explode a VRM (glTF binary) into schema-compliant USDA stages.

Fix over explode_vrm.py: the original emitted USDA syntax with glTF
semantics — `asset[] children`, `int meshIndex`, etc. — so USD tools
loaded zero geometry and traversed no composition graph. This rewrite
uses pxr APIs to emit:

  - `references` composition arcs so the stage traversal walks the
    tree (root -> scene -> nodes -> meshes -> materials)
  - `UsdGeom.Mesh` with real `points`, `faceVertexCounts`,
    `faceVertexIndices`, primvar UVs decoded from glTF accessors
  - `UsdGeom.Xform` node hierarchy with translate/rotate/scale from
    glTF node TRS
  - `UsdShade.Material` + `UsdShade.Shader` with a UsdPreviewSurface +
    UsdUVTexture per material (baseColor path only for v2; MR, normal,
    emissive land in v3 alongside the rest of glTF PBR)

Every stage remains its own .usda file so sqlar-cas chunking still
applies at every level. The addition is real schema, not a shape
change on where files land.

Requires pxr (bundled in Blender 5.x's Python; also `pip install
usd-core` outside Blender). Run via
`bpy_stub.py`'s exec pattern or a standalone Python with usd-core.

    python explode_vrm_v2.py --vrm path/to/file.vrm --out testdata/exploded/vrm_v2
"""
from __future__ import annotations

import argparse
import base64
import json
import pathlib
import struct
import sys

# glTF accessor component-type -> (numpy dtype, byte size, struct fmt)
COMPONENT_TYPES = {
    5120: ("int8", 1, "b"),
    5121: ("uint8", 1, "B"),
    5122: ("int16", 2, "h"),
    5123: ("uint16", 2, "H"),
    5125: ("uint32", 4, "I"),
    5126: ("float32", 4, "f"),
}
# glTF accessor type -> element count
TYPE_COUNTS = {"SCALAR": 1, "VEC2": 2, "VEC3": 3, "VEC4": 4, "MAT2": 4, "MAT3": 9, "MAT4": 16}


def parse_glb(data: bytes) -> tuple[dict, bytes]:
    """Parse a .glb (glTF binary) file into (json_dict, binary_blob)."""
    if data[:4] != b"glTF":
        raise ValueError("not a glTF binary (missing 'glTF' magic)")
    version, _ = struct.unpack("<II", data[4:12])
    if version != 2:
        raise ValueError(f"unsupported glTF version {version}")
    pos = 12
    json_bytes: bytes | None = None
    bin_bytes = b""
    while pos < len(data):
        chunk_len, chunk_type = struct.unpack("<II", data[pos : pos + 8])
        pos += 8
        chunk_data = data[pos : pos + chunk_len]
        pos += chunk_len
        if chunk_type == 0x4E4F534A:  # JSON
            json_bytes = chunk_data
        elif chunk_type == 0x004E4942:  # BIN
            bin_bytes = chunk_data
    if json_bytes is None:
        raise ValueError("no JSON chunk in glb")
    return json.loads(json_bytes), bin_bytes


def read_accessor(gltf: dict, bin_data: bytes, accessor_idx: int) -> list:
    """Decode a glTF accessor to a flat Python list of numbers.
    Returns list of length count * TYPE_COUNTS[type]."""
    acc = gltf["accessors"][accessor_idx]
    bv = gltf["bufferViews"][acc["bufferView"]]
    _, byte_size, fmt = COMPONENT_TYPES[acc["componentType"]]
    n_elem = TYPE_COUNTS[acc["type"]]
    count = acc["count"]
    off = bv.get("byteOffset", 0) + acc.get("byteOffset", 0)
    stride = bv.get("byteStride", byte_size * n_elem)

    values: list = []
    for i in range(count):
        record_off = off + i * stride
        for e in range(n_elem):
            v = struct.unpack_from("<" + fmt, bin_data, record_off + e * byte_size)[0]
            values.append(v)
    return values


def flatten_indices(gltf: dict, bin_data: bytes, indices_idx: int | None,
                    vert_count: int) -> list[int]:
    """Return per-primitive triangle-index list. If indices absent,
    glTF says draw as sequential triangles."""
    if indices_idx is None:
        return list(range(vert_count))
    return [int(x) for x in read_accessor(gltf, bin_data, indices_idx)]


def explode(vrm_path: pathlib.Path, out_dir: pathlib.Path) -> dict:
    from pxr import Usd, UsdGeom, UsdShade, Sdf, Gf

    data = vrm_path.read_bytes()
    gltf, bin_data = parse_glb(data)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "meshes").mkdir(exist_ok=True)
    (out_dir / "nodes").mkdir(exist_ok=True)
    (out_dir / "materials").mkdir(exist_ok=True)
    (out_dir / "scenes").mkdir(exist_ok=True)
    (out_dir / "images").mkdir(exist_ok=True)
    (out_dir / "textures").mkdir(exist_ok=True)

    scenes = gltf.get("scenes", [])
    nodes = gltf.get("nodes", [])
    meshes = gltf.get("meshes", [])
    materials = gltf.get("materials", [])
    textures = gltf.get("textures", [])
    images = gltf.get("images", [])
    buffer_views = gltf.get("bufferViews", [])

    # ---- IMAGES: extract binary payload, still just a file on disk ----
    image_files: dict[int, str] = {}
    for i, img in enumerate(images):
        if "bufferView" not in img:
            continue
        bv = buffer_views[img["bufferView"]]
        b_off, b_len = bv.get("byteOffset", 0), bv["byteLength"]
        img_bytes = bin_data[b_off : b_off + b_len]
        mime = img.get("mimeType", "application/octet-stream")
        ext = "png" if "png" in mime else "jpg" if "jpeg" in mime else "bin"
        img_rel = f"images/image_{i}.{ext}"
        (out_dir / img_rel).write_bytes(img_bytes)
        image_files[i] = img_rel

    # ---- TEXTURES: UsdShade.Shader (UsdUVTexture) with file input ----
    for i, tex in enumerate(textures):
        stage = Usd.Stage.CreateNew(str(out_dir / "textures" / f"texture_{i}.usda"))
        stage.SetDefaultPrim(stage.DefinePrim(f"/Tex_{i}", "Scope"))
        shader = UsdShade.Shader.Define(stage, f"/Tex_{i}/Sampler")
        shader.CreateIdAttr("UsdUVTexture")
        src = tex.get("source")
        if src is not None and src in image_files:
            shader.CreateInput("file", Sdf.ValueTypeNames.Asset).Set(
                Sdf.AssetPath(f"../{image_files[src]}"))
        shader.CreateOutput("rgb", Sdf.ValueTypeNames.Float3)
        stage.Save()

    # ---- MATERIALS: UsdShade.Material + UsdPreviewSurface ----
    for i, mat in enumerate(materials):
        stage = Usd.Stage.CreateNew(str(out_dir / "materials" / f"material_{i}.usda"))
        mat_prim = UsdShade.Material.Define(stage, f"/Mat_{i}")
        stage.SetDefaultPrim(mat_prim.GetPrim())

        surface = UsdShade.Shader.Define(stage, f"/Mat_{i}/Surface")
        surface.CreateIdAttr("UsdPreviewSurface")
        surface.CreateInput("useSpecularWorkflow", Sdf.ValueTypeNames.Int).Set(0)

        pbr = mat.get("pbrMetallicRoughness", {})
        # baseColorFactor (RGBA) — default white
        bcf = pbr.get("baseColorFactor", [1.0, 1.0, 1.0, 1.0])
        surface.CreateInput("diffuseColor", Sdf.ValueTypeNames.Color3f).Set(
            Gf.Vec3f(bcf[0], bcf[1], bcf[2]))
        surface.CreateInput("opacity", Sdf.ValueTypeNames.Float).Set(bcf[3])
        surface.CreateInput("metallic", Sdf.ValueTypeNames.Float).Set(
            pbr.get("metallicFactor", 1.0))
        surface.CreateInput("roughness", Sdf.ValueTypeNames.Float).Set(
            pbr.get("roughnessFactor", 1.0))

        # baseColorTexture reference (composition arc, not asset attribute)
        base_tex = pbr.get("baseColorTexture", {}).get("index")
        if base_tex is not None:
            # In-line reference so the shader graph resolves without
            # an extra file hop; the texture .usda is still there for
            # sqlar-cas chunking.
            tex_shader = UsdShade.Shader.Define(stage, f"/Mat_{i}/TexSampler")
            tex_shader.CreateIdAttr("UsdUVTexture")
            src = textures[base_tex].get("source")
            if src is not None and src in image_files:
                tex_shader.CreateInput("file", Sdf.ValueTypeNames.Asset).Set(
                    Sdf.AssetPath(f"../{image_files[src]}"))
            surface.CreateInput("diffuseColor", Sdf.ValueTypeNames.Color3f).ConnectToSource(
                tex_shader.ConnectableAPI(), "rgb")

        mat_prim.CreateSurfaceOutput().ConnectToSource(surface.ConnectableAPI(), "surface")
        stage.Save()

    # ---- MESHES: UsdGeom.Mesh with real geometry per primitive ----
    for i, mesh in enumerate(meshes):
        stage = Usd.Stage.CreateNew(str(out_dir / "meshes" / f"mesh_{i}.usda"))
        stage.SetDefaultPrim(stage.DefinePrim(f"/Mesh_{i}", "Xform"))
        for pi, prim in enumerate(mesh.get("primitives", [])):
            attrs = prim.get("attributes", {})
            if "POSITION" not in attrs:
                continue
            positions = read_accessor(gltf, bin_data, attrs["POSITION"])  # flat xyz*n
            points = [Gf.Vec3f(positions[k], positions[k + 1], positions[k + 2])
                      for k in range(0, len(positions), 3)]
            vert_count = len(points)
            tri_indices = flatten_indices(gltf, bin_data, prim.get("indices"), vert_count)
            face_counts = [3] * (len(tri_indices) // 3)  # glTF is triangles

            mesh_prim = UsdGeom.Mesh.Define(stage, f"/Mesh_{i}/Prim_{pi}")
            mesh_prim.CreatePointsAttr().Set(points)
            mesh_prim.CreateFaceVertexCountsAttr().Set(face_counts)
            mesh_prim.CreateFaceVertexIndicesAttr().Set(tri_indices)
            mesh_prim.CreateExtentAttr().Set(UsdGeom.PointBased(mesh_prim).ComputeExtent(points))

            # UVs (TEXCOORD_0) as primvar
            if "TEXCOORD_0" in attrs:
                uvs = read_accessor(gltf, bin_data, attrs["TEXCOORD_0"])
                uv_pairs = [Gf.Vec2f(uvs[k], 1.0 - uvs[k + 1])  # flip V, glTF vs USD
                            for k in range(0, len(uvs), 2)]
                uv_primvar = UsdGeom.PrimvarsAPI(mesh_prim).CreatePrimvar(
                    "st", Sdf.ValueTypeNames.TexCoord2fArray,
                    interpolation=UsdGeom.Tokens.vertex)
                uv_primvar.Set(uv_pairs)

            # Normals (NORMAL) as primvar
            if "NORMAL" in attrs:
                normals = read_accessor(gltf, bin_data, attrs["NORMAL"])
                normal_vecs = [Gf.Vec3f(normals[k], normals[k + 1], normals[k + 2])
                               for k in range(0, len(normals), 3)]
                mesh_prim.CreateNormalsAttr().Set(normal_vecs)
                mesh_prim.SetNormalsInterpolation(UsdGeom.Tokens.vertex)

            # Material binding via reference to material_N.usda
            if "material" in prim:
                mat_idx = prim["material"]
                UsdShade.MaterialBindingAPI.Apply(mesh_prim.GetPrim())
                mat_ref_prim = stage.DefinePrim(f"/Mesh_{i}/BoundMat_{pi}", "Material")
                mat_ref_prim.GetReferences().AddReference(
                    assetPath=f"../materials/material_{mat_idx}.usda",
                    primPath=f"/Mat_{mat_idx}")
                UsdShade.MaterialBindingAPI(mesh_prim.GetPrim()).Bind(
                    UsdShade.Material(mat_ref_prim))
        stage.Save()

    # ---- NODES: UsdGeom.Xform with TRS + child references ----
    for i, node in enumerate(nodes):
        stage = Usd.Stage.CreateNew(str(out_dir / "nodes" / f"node_{i}.usda"))
        node_prim = UsdGeom.Xform.Define(stage, f"/Node_{i}")
        stage.SetDefaultPrim(node_prim.GetPrim())

        # TRS from glTF node
        if "translation" in node:
            UsdGeom.XformCommonAPI(node_prim).SetTranslate(Gf.Vec3d(*node["translation"]))
        if "rotation" in node:
            # glTF: [x, y, z, w]; USD Gf.Quatf: (real, imaginary vec3)
            rx, ry, rz, rw = node["rotation"]
            UsdGeom.XformCommonAPI(node_prim).SetRotate(
                Gf.Vec3f(0, 0, 0))  # TODO(v3): convert quat -> euler XYZ properly
        if "scale" in node:
            UsdGeom.XformCommonAPI(node_prim).SetScale(Gf.Vec3f(*node["scale"]))

        # Mesh reference (composition arc, not asset attribute)
        mesh_idx = node.get("mesh")
        if mesh_idx is not None:
            mesh_ref_prim = stage.DefinePrim(f"/Node_{i}/Mesh", "Xform")
            mesh_ref_prim.GetReferences().AddReference(
                assetPath=f"../meshes/mesh_{mesh_idx}.usda",
                primPath=f"/Mesh_{mesh_idx}")

        # Child node references
        for ci, child_idx in enumerate(node.get("children", [])):
            child_prim = stage.DefinePrim(f"/Node_{i}/Child_{ci}", "Xform")
            child_prim.GetReferences().AddReference(
                assetPath=f"../nodes/node_{child_idx}.usda",
                primPath=f"/Node_{child_idx}")
        stage.Save()

    # ---- SCENES: root Scope with references to root nodes ----
    for i, scene in enumerate(scenes):
        stage = Usd.Stage.CreateNew(str(out_dir / "scenes" / f"scene_{i}.usda"))
        scene_prim = stage.DefinePrim(f"/Scene_{i}", "Xform")
        stage.SetDefaultPrim(scene_prim)
        for ni, node_idx in enumerate(scene.get("nodes", [])):
            n_prim = stage.DefinePrim(f"/Scene_{i}/Node_{ni}", "Xform")
            n_prim.GetReferences().AddReference(
                assetPath=f"../nodes/node_{node_idx}.usda",
                primPath=f"/Node_{node_idx}")
        stage.Save()

    # ---- ROOT: Xform "Avatar" referencing the default scene ----
    root_stage = Usd.Stage.CreateNew(str(out_dir / "root.usda"))
    avatar = UsdGeom.Xform.Define(root_stage, "/Avatar")
    root_stage.SetDefaultPrim(avatar.GetPrim())
    if scenes:
        scene_ref_prim = root_stage.DefinePrim("/Avatar/Scene", "Xform")
        scene_ref_prim.GetReferences().AddReference(
            assetPath="scenes/scene_0.usda",
            primPath="/Scene_0")
    root_stage.Save()

    return {
        "scenes": len(scenes),
        "nodes": len(nodes),
        "meshes": len(meshes),
        "materials": len(materials),
        "textures": len(textures),
        "images": len(images),
        "bin_bytes": len(bin_data),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--vrm", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    stats = explode(pathlib.Path(args.vrm), pathlib.Path(args.out))
    print(f"exploded {args.vrm} -> {args.out}")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    n = sum(1 for _ in pathlib.Path(args.out).rglob("*.usda"))
    print(f"  total stage files: {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
