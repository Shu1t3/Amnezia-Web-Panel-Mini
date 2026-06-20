package embeds

import _ "embed"

//go:embed protocol_telemt/config.toml
var TelemtConfigToml []byte

//go:embed protocol_telemt/docker-compose.yml
var TelemtDockerCompose []byte

//go:embed protocol_telemt/Dockerfile
var TelemtDockerfile []byte
