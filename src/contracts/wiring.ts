export type RuntimePaths = {
  launcherPath: string;
};

export type WiringEntry = {
  hookEvent: string;
  handler: string;
  command: string;
  args: string[];
  timeoutSeconds: number;
  failClosed?: boolean;
  matcher?: string;
  loopLimit?: number;
};

/**
 * why `file`: a host that loads in-process plugins instead of running hook commands has no hook document to merge
 * into or replace. Its wiring is one whole file the provider renders, and install, doctor and uninstall handle it
 * by strategy alone, without learning the provider's name ([/decisions/ad-147.md](/decisions/ad-147.md)).
 */
export type ProviderWiring =
  | { target: string; strategy: "replace" | "merge"; entries: WiringEntry[] }
  | {
      target: string;
      strategy: "file";
      entries: WiringEntry[];
      content: string;
      // why: the file's own directory may not exist yet on a machine where the host is installed, so presence is
      // decided by the host's config directory instead.
      hostDir: string;
    };
