# Brand assets

Home Assistant shows an integration's icon from the [brands](https://github.com/home-assistant/brands)
repository; a custom integration appears with "icon not available" until its assets are merged
there. To add them, open a pull request against that repository with these files under
`custom_integrations/cloudflare_access_relay/`:

- `icon.png` (256×256) and `icon@2x.png` (512×512): this directory.

The same drawing is `logo.png` at the repository root, the logo of the project's Cloudflare
OAuth client.
