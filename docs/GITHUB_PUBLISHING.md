# Japanese port GitHub publication

The project has been forked to [`yellowblitz/dw5xl-recomp`](https://github.com/yellowblitz/dw5xl-recomp). Development stays on `jp-port` and the inherited PAL `main` is left unchanged.

The JP branch contains only source, tests, static documentation and hash/header metadata; no uploaded game binaries are committed. The Japanese native game is **not built or playable** yet.

To enable the static project page, open the fork's **Settings → Pages → Build and deployment → Deploy from a branch**; select `jp-port` and `/docs`, then save. This setting is not changed by committing HTML. GitHub will then show the public website URL and deployment status in the Pages settings.

Run tests before each change:

```powershell
python -m unittest discover -s tools/jp -p "test_*.py" -v
```

Keep game files under the existing ignored `/game/` directory only. Never commit discs, executable code, IRX modules, video/audio or generated translation output. Preserve all GPL and third-party notices.
