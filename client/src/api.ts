import { invoke } from "@tauri-apps/api/core";

export interface ServerInfo {
  id: string;
  name: string;
  country: string;
  city: string;
  protocol: string;
}

export interface AppStatus {
  has_subscription: boolean;
  expires: string | null;
  servers: ServerInfo[];
  connected: boolean;
  connected_server: string | null;
}

export const api = {
  setSubscription: (url: string) => invoke<AppStatus>("set_subscription", { url }),
  refreshServers: () => invoke<AppStatus>("refresh_servers"),
  connect: (serverId: string) => invoke<AppStatus>("connect", { serverId }),
  disconnect: () => invoke<AppStatus>("disconnect"),
  status: () => invoke<AppStatus>("status"),
  publicIp: () => invoke<string>("public_ip"),
  forgetSubscription: () => invoke<void>("forget_subscription"),
};
