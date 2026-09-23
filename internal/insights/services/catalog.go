package services

// catalog lists services by the domains they own. A suffix covers the domain
// and everything under it. Shared infrastructure, such as googleapis.com,
// cloudfront.net, or akamaized.net, is left out on purpose: it serves many
// unrelated apps, so naming one of them would be a guess.
var catalog = []catalogEntry{
	// Streaming video.
	{Service{"youtube", "YouTube", CategoryStreaming}, []string{"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be", "youtube-nocookie.com", "youtubei.googleapis.com"}},
	{Service{"netflix", "Netflix", CategoryStreaming}, []string{"netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflximg.com", "nflxext.com", "nflxso.net"}},
	{Service{"disney-plus", "Disney+", CategoryStreaming}, []string{"disneyplus.com", "disney-plus.net", "bamgrid.com", "dssott.com"}},
	{Service{"prime-video", "Prime Video", CategoryStreaming}, []string{"primevideo.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net", "pv-cdn.net"}},
	{Service{"hulu", "Hulu", CategoryStreaming}, []string{"hulu.com", "huluim.com", "hulustream.com"}},
	{Service{"max", "Max", CategoryStreaming}, []string{"max.com", "hbomax.com", "hbo.com", "hbonow.com"}},
	{Service{"apple-tv", "Apple TV", CategoryStreaming}, []string{"tv.apple.com", "hls.itunes.apple.com", "play-edge.itunes.apple.com"}},
	{Service{"peacock", "Peacock", CategoryStreaming}, []string{"peacocktv.com"}},
	{Service{"paramount-plus", "Paramount+", CategoryStreaming}, []string{"paramountplus.com", "cbsivideo.com", "pplusstatic.com"}},
	{Service{"twitch", "Twitch", CategoryStreaming}, []string{"twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net"}},
	{Service{"plex", "Plex", CategoryStreaming}, []string{"plex.tv", "plex.direct", "plexapp.com"}},
	{Service{"roku", "Roku", CategoryStreaming}, []string{"roku.com", "rokutime.com", "ravm.tv"}},
	{Service{"crunchyroll", "Crunchyroll", CategoryStreaming}, []string{"crunchyroll.com", "vrv.co"}},
	{Service{"pluto-tv", "Pluto TV", CategoryStreaming}, []string{"pluto.tv"}},
	{Service{"tubi", "Tubi", CategoryStreaming}, []string{"tubi.tv", "tubitv.com"}},
	{Service{"youtube-tv", "YouTube TV", CategoryStreaming}, []string{"tv.youtube.com"}},
	{Service{"sling", "Sling TV", CategoryStreaming}, []string{"sling.com", "movetv.com"}},
	{Service{"vimeo", "Vimeo", CategoryStreaming}, []string{"vimeo.com", "vimeocdn.com"}},

	// Music and audio.
	{Service{"spotify", "Spotify", CategoryMusic}, []string{"spotify.com", "scdn.co", "spotifycdn.com", "spotifycdn.net", "spotilocal.com", "spotify.design"}},
	{Service{"apple-music", "Apple Music", CategoryMusic}, []string{"music.apple.com", "aod.itunes.apple.com"}},
	{Service{"pandora", "Pandora", CategoryMusic}, []string{"pandora.com", "p-cdn.com", "p-cdn.us"}},
	{Service{"soundcloud", "SoundCloud", CategoryMusic}, []string{"soundcloud.com", "sndcdn.com"}},
	{Service{"sonos", "Sonos", CategoryMusic}, []string{"sonos.com", "sonos.net"}},
	{Service{"audible", "Audible", CategoryMusic}, []string{"audible.com", "audible.co.uk"}},
	{Service{"tidal", "Tidal", CategoryMusic}, []string{"tidal.com", "tidalhifi.com"}},
	{Service{"siriusxm", "SiriusXM", CategoryMusic}, []string{"siriusxm.com", "sirius.com"}},

	// Social.
	{Service{"facebook", "Facebook", CategorySocial}, []string{"facebook.com", "facebook.net", "fbcdn.net", "fbsbx.com", "fb.com"}},
	{Service{"instagram", "Instagram", CategorySocial}, []string{"instagram.com", "cdninstagram.com"}},
	{Service{"tiktok", "TikTok", CategorySocial}, []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "tiktokcdn-us.com", "ttwstatic.com", "byteoversea.com", "ibytedtos.com", "musical.ly"}},
	{Service{"x", "X", CategorySocial}, []string{"x.com", "twitter.com", "twimg.com", "t.co"}},
	{Service{"snapchat", "Snapchat", CategorySocial}, []string{"snapchat.com", "sc-cdn.net", "snap-dev.net", "sc-static.net", "snapkit.com"}},
	{Service{"reddit", "Reddit", CategorySocial}, []string{"reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"}},
	{Service{"pinterest", "Pinterest", CategorySocial}, []string{"pinterest.com", "pinimg.com"}},
	{Service{"linkedin", "LinkedIn", CategorySocial}, []string{"linkedin.com", "licdn.com"}},
	{Service{"threads", "Threads", CategorySocial}, []string{"threads.net", "threads.com"}},
	{Service{"bluesky", "Bluesky", CategorySocial}, []string{"bsky.app", "bsky.social", "bsky.network"}},
	{Service{"tumblr", "Tumblr", CategorySocial}, []string{"tumblr.com"}},

	// Messaging.
	{Service{"whatsapp", "WhatsApp", CategoryMessaging}, []string{"whatsapp.com", "whatsapp.net", "wa.me"}},
	{Service{"messenger", "Messenger", CategoryMessaging}, []string{"messenger.com"}},
	{Service{"signal", "Signal", CategoryMessaging}, []string{"signal.org", "whispersystems.org", "signal.art"}},
	{Service{"telegram", "Telegram", CategoryMessaging}, []string{"telegram.org", "telegram.me", "t.me", "telesco.pe", "tdesktop.com"}},
	{Service{"discord", "Discord", CategoryMessaging}, []string{"discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com"}},
	{Service{"slack", "Slack", CategoryMessaging}, []string{"slack.com", "slack-edge.com", "slack-msgs.com", "slack-imgs.com", "slackb.com"}},
	{Service{"imessage", "iMessage and FaceTime", CategoryMessaging}, []string{"ess.apple.com", "identity.apple.com", "facetime.apple.com"}},

	// Video calls.
	{Service{"zoom", "Zoom", CategoryCalls}, []string{"zoom.us", "zoom.com", "zoomgov.com"}},
	{Service{"teams", "Microsoft Teams", CategoryCalls}, []string{"teams.microsoft.com", "teams.live.com", "teams.cloud.microsoft", "skype.com", "lync.com"}},
	{Service{"google-meet", "Google Meet", CategoryCalls}, []string{"meet.google.com"}},
	{Service{"webex", "Webex", CategoryCalls}, []string{"webex.com", "wbx2.com"}},

	// Gaming.
	{Service{"steam", "Steam", CategoryGaming}, []string{"steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "steamserver.net", "steamgames.com", "steamusercontent.com"}},
	{Service{"xbox", "Xbox", CategoryGaming}, []string{"xbox.com", "xboxlive.com", "xboxservices.com", "gamepass.com"}},
	{Service{"playstation", "PlayStation", CategoryGaming}, []string{"playstation.com", "playstation.net", "sonyentertainmentnetwork.com", "psn.com"}},
	{Service{"nintendo", "Nintendo", CategoryGaming}, []string{"nintendo.com", "nintendo.net", "nintendo.co.jp", "nintendowifi.net"}},
	{Service{"epic-games", "Epic Games", CategoryGaming}, []string{"epicgames.com", "epicgames.dev", "unrealengine.com", "fortnite.com"}},
	{Service{"roblox", "Roblox", CategoryGaming}, []string{"roblox.com", "rbxcdn.com", "rbx.com", "robloxlabs.com"}},
	{Service{"minecraft", "Minecraft", CategoryGaming}, []string{"minecraft.net", "mojang.com", "minecraftservices.com"}},
	{Service{"battle-net", "Battle.net", CategoryGaming}, []string{"battle.net", "blizzard.com", "blzstatic.cn"}},
	{Service{"ea", "EA", CategoryGaming}, []string{"ea.com", "origin.com"}},
	{Service{"riot-games", "Riot Games", CategoryGaming}, []string{"riotgames.com", "leagueoflegends.com", "riotcdn.net"}},

	// Shopping.
	{Service{"amazon", "Amazon", CategoryShopping}, []string{"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "media-amazon.com", "ssl-images-amazon.com"}},
	{Service{"ebay", "eBay", CategoryShopping}, []string{"ebay.com", "ebayimg.com", "ebaystatic.com"}},
	{Service{"etsy", "Etsy", CategoryShopping}, []string{"etsy.com", "etsystatic.com"}},
	{Service{"walmart", "Walmart", CategoryShopping}, []string{"walmart.com", "walmartimages.com"}},
	{Service{"target", "Target", CategoryShopping}, []string{"target.com", "targetimg1.com"}},
	{Service{"temu", "Temu", CategoryShopping}, []string{"temu.com", "kwcdn.com"}},
	{Service{"shein", "Shein", CategoryShopping}, []string{"shein.com", "ltwebstatic.com"}},

	// Smart home.
	{Service{"alexa", "Alexa", CategorySmartHome}, []string{"alexa.amazon.com", "avs-alexa-na.amazon.com", "alexa.a2z.com", "amazonalexa.com"}},
	{Service{"google-home", "Google Home", CategorySmartHome}, []string{"home.google.com", "nest.com", "home.nest.com", "dropcam.com"}},
	{Service{"smartthings", "SmartThings", CategorySmartHome}, []string{"smartthings.com", "samsungiotcloud.com"}},
	{Service{"philips-hue", "Philips Hue", CategorySmartHome}, []string{"meethue.com", "philips-hue.com"}},
	{Service{"ecobee", "ecobee", CategorySmartHome}, []string{"ecobee.com"}},
	{Service{"tuya", "Tuya Smart", CategorySmartHome}, []string{"tuya.com", "tuyaus.com", "tuyaeu.com", "tuyacn.com"}},
	{Service{"tp-link-kasa", "TP-Link Kasa and Tapo", CategorySmartHome}, []string{"tplinkcloud.com", "tplinknbu.com", "tplinkra.com", "kasasmart.com", "tapo.com"}},
	{Service{"home-assistant", "Home Assistant", CategorySmartHome}, []string{"home-assistant.io", "nabucasa.com", "ui.nabu.casa"}},
	{Service{"homekit", "Apple Home", CategorySmartHome}, []string{"homekit.apple.com"}},
	{Service{"myq", "myQ", CategorySmartHome}, []string{"myq-cloud.com", "myqservices.com", "chamberlain.com"}},
	{Service{"roomba", "iRobot", CategorySmartHome}, []string{"irobot.com", "irobotapi.com"}},
	{Service{"ifttt", "IFTTT", CategorySmartHome}, []string{"ifttt.com"}},

	// Cameras and doorbells.
	{Service{"ring", "Ring", CategoryCameras}, []string{"ring.com", "ring.devices.a2z.com"}},
	{Service{"wyze", "Wyze", CategoryCameras}, []string{"wyze.com", "wyzecam.com"}},
	{Service{"arlo", "Arlo", CategoryCameras}, []string{"arlo.com", "arlo.net", "netgear-arlo.com"}},
	{Service{"blink", "Blink", CategoryCameras}, []string{"immedia-semi.com", "blinkforhome.com"}},
	{Service{"eufy", "eufy", CategoryCameras}, []string{"eufylife.com", "eufy.com"}},
	{Service{"simplisafe", "SimpliSafe", CategoryCameras}, []string{"simplisafe.com"}},
	
	// Cloud storage and backup.
	{Service{"icloud", "iCloud", CategoryCloud}, []string{"icloud.com", "icloud-content.com", "apple-cloudkit.com", "me.com"}},
	{Service{"google-drive", "Google Drive", CategoryCloud}, []string{"drive.google.com", "docs.google.com", "drive.usercontent.google.com"}},
	{Service{"onedrive", "OneDrive", CategoryCloud}, []string{"onedrive.com", "onedrive.live.com", "1drv.com", "1drv.ms", "sharepoint.com"}},
	{Service{"dropbox", "Dropbox", CategoryCloud}, []string{"dropbox.com", "dropboxapi.com", "dropboxstatic.com", "dropboxusercontent.com", "db.tt"}},
	{Service{"backblaze", "Backblaze", CategoryCloud}, []string{"backblaze.com", "backblazeb2.com"}},
	{Service{"box", "Box", CategoryCloud}, []string{"box.com", "box.net", "boxcdn.net"}},
	{Service{"google-photos", "Google Photos", CategoryCloud}, []string{"photos.google.com", "photos.googleapis.com"}},

	// Productivity.
	{Service{"microsoft-365", "Microsoft 365", CategoryProductivity}, []string{"office.com", "office.net", "office365.com", "outlook.com", "outlook.office.com", "live.com", "microsoftonline.com", "cloud.microsoft"}},
	{Service{"gmail", "Gmail", CategoryProductivity}, []string{"mail.google.com", "gmail.com"}},
	{Service{"notion", "Notion", CategoryProductivity}, []string{"notion.so", "notion.com", "notion.site", "notion-static.com"}},
	{Service{"figma", "Figma", CategoryProductivity}, []string{"figma.com"}},
	{Service{"asana", "Asana", CategoryProductivity}, []string{"asana.com"}},
	{Service{"miro", "Miro", CategoryProductivity}, []string{"miro.com", "miro.io"}},
	{Service{"linear", "Linear", CategoryProductivity}, []string{"linear.app"}},
	{Service{"loom", "Loom", CategoryProductivity}, []string{"loom.com"}},
	{Service{"calendly", "Calendly", CategoryProductivity}, []string{"calendly.com"}},
	{Service{"docusign", "DocuSign", CategoryProductivity}, []string{"docusign.com", "docusign.net"}},
	{Service{"trello", "Trello", CategoryProductivity}, []string{"trello.com"}},
	{Service{"atlassian", "Atlassian", CategoryProductivity}, []string{"atlassian.com", "atlassian.net", "atl-paas.net"}},
	{Service{"salesforce", "Salesforce", CategoryProductivity}, []string{"salesforce.com", "force.com"}},
	{Service{"canva", "Canva", CategoryProductivity}, []string{"canva.com"}},
	{Service{"grammarly", "Grammarly", CategoryProductivity}, []string{"grammarly.com", "grammarly.io"}},
	{Service{"adobe", "Adobe", CategoryProductivity}, []string{"adobe.com", "adobe.io", "adobelogin.com", "typekit.net", "adobecc.com"}},
	{Service{"1password", "1Password", CategorySecurity}, []string{"1password.com", "1password.ca", "1password.eu", "agilebits.com"}},
	{Service{"bitwarden", "Bitwarden", CategorySecurity}, []string{"bitwarden.com", "bitwarden.net", "bitwarden.eu"}},
	{Service{"lastpass", "LastPass", CategorySecurity}, []string{"lastpass.com", "lastpass.eu"}},
	{Service{"tailscale", "Tailscale", CategorySecurity}, []string{"tailscale.com", "tailscale.io", "ts.net"}},
	{Service{"nordvpn", "NordVPN", CategorySecurity}, []string{"nordvpn.com", "nordcdn.com", "nordvpn.net"}},
	{Service{"expressvpn", "ExpressVPN", CategorySecurity}, []string{"expressvpn.com", "expressapisv2.net"}},
	{Service{"proton", "Proton", CategorySecurity}, []string{"proton.me", "protonmail.com", "protonvpn.com", "protonmail.ch"}},
	{Service{"mullvad", "Mullvad VPN", CategorySecurity}, []string{"mullvad.net"}},
	{Service{"malwarebytes", "Malwarebytes", CategorySecurity}, []string{"malwarebytes.com", "mwbsys.com"}},

	// Developer tools.
	{Service{"github", "GitHub", CategoryDeveloper}, []string{"github.com", "githubusercontent.com", "githubassets.com", "github.io", "ghcr.io", "githubcopilot.com"}},
	{Service{"gitlab", "GitLab", CategoryDeveloper}, []string{"gitlab.com", "gitlab-static.net"}},
	{Service{"docker", "Docker", CategoryDeveloper}, []string{"docker.com", "docker.io"}},
	{Service{"npm", "npm", CategoryDeveloper}, []string{"npmjs.com", "npmjs.org"}},
	{Service{"vscode", "Visual Studio Code", CategoryDeveloper}, []string{"vscode-cdn.net", "visualstudio.com", "vsassets.io", "vscode.dev"}},
	{Service{"jetbrains", "JetBrains", CategoryDeveloper}, []string{"jetbrains.com", "jetbrains.space"}},
	{Service{"go-modules", "Go modules", CategoryDeveloper}, []string{"proxy.golang.org", "sum.golang.org", "golang.org", "go.dev"}},
	{Service{"python-packages", "Python packages", CategoryDeveloper}, []string{"pypi.org", "pythonhosted.org"}},
	{Service{"homebrew", "Homebrew", CategoryDeveloper}, []string{"brew.sh", "formulae.brew.sh"}},

	// AI assistants.
	{Service{"chatgpt", "ChatGPT", CategoryAI}, []string{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"}},
	{Service{"claude", "Claude", CategoryAI}, []string{"claude.ai", "anthropic.com", "claude.com", "claudeusercontent.com"}},
	{Service{"gemini", "Gemini", CategoryAI}, []string{"gemini.google.com"}},
	{Service{"copilot", "Microsoft Copilot", CategoryAI}, []string{"copilot.microsoft.com"}},
	{Service{"perplexity", "Perplexity", CategoryAI}, []string{"perplexity.ai"}},

	// News and reading.
	{Service{"nytimes", "The New York Times", CategoryNews}, []string{"nytimes.com", "nyt.com"}},
	{Service{"cnn", "CNN", CategoryNews}, []string{"cnn.com", "cnn.io"}},
	{Service{"bbc", "BBC", CategoryNews}, []string{"bbc.com", "bbc.co.uk", "bbci.co.uk"}},
	{Service{"wikipedia", "Wikipedia", CategoryNews}, []string{"wikipedia.org", "wikimedia.org", "wikidata.org"}},
	{Service{"kindle", "Kindle", CategoryNews}, []string{"kindle.amazon.com", "read.amazon.com"}},
	{Service{"substack", "Substack", CategoryNews}, []string{"substack.com", "substackcdn.com"}},

	// Search.
	{Service{"google-search", "Google", CategorySearch}, []string{"google.com"}},
	{Service{"bing", "Bing", CategorySearch}, []string{"bing.com", "bing.net"}},
	{Service{"duckduckgo", "DuckDuckGo", CategorySearch}, []string{"duckduckgo.com", "duck.com"}},
	{Service{"kagi", "Kagi", CategorySearch}, []string{"kagi.com"}},

	// Device platforms: the phone-home traffic of an operating system itself.
	{Service{"apple", "Apple services", CategoryPlatform}, []string{"apple.com", "mzstatic.com", "apple-dns.net", "aaplimg.com", "cdn-apple.com", "itunes.apple.com"}},
	{Service{"apple-updates", "Apple software updates", CategoryPlatform}, []string{"mesu.apple.com", "swdist.apple.com", "swscan.apple.com", "updates.cdn-apple.com", "gdmf.apple.com"}},
	{Service{"windows-update", "Windows Update", CategoryPlatform}, []string{"windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "dl.delivery.mp.microsoft.com"}},
	{Service{"microsoft", "Microsoft services", CategoryPlatform}, []string{"microsoft.com", "msftconnecttest.com", "msftncsi.com", "windows.com", "msn.com", "msedge.net"}},
	{Service{"android", "Android", CategoryPlatform}, []string{"android.com", "android.clients.google.com", "play.googleapis.com", "connectivitycheck.gstatic.com"}},
	{Service{"google-play", "Google Play", CategoryPlatform}, []string{"play.google.com", "ggpht.com"}},
	{Service{"samsung", "Samsung services", CategoryPlatform}, []string{"samsung.com", "samsungcloud.com", "samsungosp.com", "samsungqbe.com", "samsungapps.com", "samsungcloudsolution.com", "samsungcloudsolution.net"}},
	{Service{"lg-webos", "LG webOS", CategoryPlatform}, []string{"lgtvsdp.com", "lgappstv.com", "lge.com", "lgsmartad.com"}},
	{Service{"vizio", "Vizio", CategoryPlatform}, []string{"vizio.com", "vizio.net", "viziocdn.com"}},
	{Service{"fire-tv", "Fire TV", CategoryPlatform}, []string{"amazon-dss.com", "firetvcaptiveportal.com"}},
	{Service{"chromecast", "Chromecast", CategoryPlatform}, []string{"cast.google.com", "chromecast.com"}},
	{Service{"unifi", "UniFi", CategoryPlatform}, []string{"ui.com", "ubnt.com", "unifi-ai.com"}},
	{Service{"ubuntu", "Ubuntu", CategoryPlatform}, []string{"ubuntu.com", "canonical.com", "snapcraft.io", "snapcraftcontent.com"}},
	{Service{"debian", "Debian", CategoryPlatform}, []string{"debian.org"}},
	{Service{"raspberry-pi", "Raspberry Pi", CategoryPlatform}, []string{"raspberrypi.com", "raspberrypi.org"}},
	{Service{"synology", "Synology", CategoryPlatform}, []string{"synology.com", "quickconnect.to", "synology.me"}},
	{Service{"qnap", "QNAP", CategoryPlatform}, []string{"qnap.com", "myqnapcloud.com"}},
	{Service{"hp-printing", "HP printing", CategoryPlatform}, []string{"hpeprint.com", "hpsmart.com", "hpconnected.com"}},
	{Service{"epson", "Epson", CategoryPlatform}, []string{"epson.com", "epsonconnect.com", "epson.net"}},
	{Service{"brother", "Brother", CategoryPlatform}, []string{"brother.com", "brother-usa.com"}},
	{Service{"ntp", "Time sync", CategoryPlatform}, []string{"pool.ntp.org", "time.apple.com", "time.windows.com", "time.google.com", "time.cloudflare.com"}},

	// Finance.
	{Service{"paypal", "PayPal", CategoryFinance}, []string{"paypal.com", "paypalobjects.com", "venmo.com"}},
	{Service{"coinbase", "Coinbase", CategoryFinance}, []string{"coinbase.com"}},
	{Service{"robinhood", "Robinhood", CategoryFinance}, []string{"robinhood.com"}},
}
