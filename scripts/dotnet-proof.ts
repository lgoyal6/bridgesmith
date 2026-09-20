/**
 * End-to-end .NET proof. Generates a client from an actual partial
 * certification, compiles it, calls a guarded facade, and proves that the
 * uncovered operation is absent from the package and refused by the facade.
 */
import { mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execa } from "execa";
import { loadHar } from "../src/capture/har.js";
import { deriveSpec } from "../src/spec/derive.js";
import { certify } from "../src/certify/certify.js";
import { issueCertificate } from "../src/registry/certificate.js";
import { generateDotnetPackage, writeDotnetPackage } from "../src/codegen/dotnet.js";
import { buildRestApp } from "../src/surfaces/rest.js";
import { captureA, captureB } from "../test/fixtures.js";

const root = mkdtempSync(join(tmpdir(), "bridgesmith-dotnet-proof-"));
const registry = join(root, "registry");
let server: ReturnType<ReturnType<typeof buildRestApp>["listen"]> | undefined;

try {
  const derivePath = join(root, "derive.har");
  const holdoutPath = join(root, "holdout.har");
  const deriveHar = captureA();
  const fullHoldout = captureB() as { log: { entries: Array<{ request: { url: string } }> } };
  const partialHoldout = {
    log: {
      ...fullHoldout.log,
      entries: fullHoldout.log.entries.filter((entry) => /\/api\/events\/evt_100[78]$/.test(entry.request.url)),
    },
  };
  writeFileSync(derivePath, JSON.stringify(deriveHar));
  writeFileSync(holdoutPath, JSON.stringify(partialHoldout));
  const derive = loadHar(derivePath);
  const holdout = loadHar(holdoutPath);
  const spec = deriveSpec(derive, { app: "events", captureLabel: "dotnet-proof", host: "example-events.com" });
  const { report } = await certify(spec, holdout, { deriveExchanges: derive, maxRepairs: 0 });
  if (!report.certifiedOps.includes("get_api_events_event_id") || !report.uncoveredOps.includes("get_api_events")) {
    throw new Error(`proof fixture did not produce the expected partial certification: ${JSON.stringify({ certified: report.certifiedOps, refused: report.refusedOps, uncovered: report.uncoveredOps })}`);
  }
  const cert = issueCertificate(spec, report, 1, registry);
  const packageDir = writeDotnetPackage(root, generateDotnetPackage(spec, cert));

  const app = buildRestApp(spec, cert, {
    apiKey: "proof-key",
    unguarded: true,
    fetcher: async () => ({
      status: 200,
      headers: { get: () => "application/json" },
      json: async () => ({
        id: "evt_1007",
        title: "Event 7",
        status: "published",
        startDate: "2026-09-08T18:00:00Z",
        capacity: 57,
        venue: "Venue 7",
      }),
      text: async () => "",
    }),
  });
  server = app.listen(0);
  await new Promise<void>((resolve, reject) => {
    server!.once("listening", resolve);
    server!.once("error", reject);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("proof server did not bind a TCP port");

  const proofDir = join(root, "Proof");
  const relativeProject = `../${packageDir.split("/").at(-1)!}/Events.Bridgesmith.csproj`;
  mkdirSync(proofDir, { recursive: true });
  writeFileSync(join(proofDir, "Proof.csproj"), `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup><ProjectReference Include="${relativeProject}" /></ItemGroup>
</Project>
`);
  writeFileSync(join(proofDir, "Program.cs"), `using System.Net.Http.Json;
using Bridgesmith.Connectors.Events;

var methods = typeof(EventsClient).GetMethods().Select(m => m.Name).ToHashSet(StringComparer.Ordinal);
if (!methods.Contains("GetApiEventsEventIdAsync")) throw new Exception("certified operation is missing");
if (methods.Contains("GetApiEventsAsync")) throw new Exception("uncertified operation leaked into generated surface");

using var http = new HttpClient();
var baseUri = new Uri("http://127.0.0.1:${address.port}/");
var client = new EventsClient(http, baseUri, "proof-key");
var result = await client.GetApiEventsEventIdAsync(new GetApiEventsEventIdRequest { EventId = "evt_1007" });
if (result.Id != "evt_1007" || result.Title != "Event 7") throw new Exception("certified call returned wrong typed data");

var driftHandler = new DriftedManifestHandler();
var driftedClient = new EventsClient(new HttpClient(driftHandler), baseUri, "proof-key");
try
{
    await driftedClient.GetApiEventsEventIdAsync(new GetApiEventsEventIdRequest { EventId = "evt_1007" });
    throw new Exception("identity drift was accepted");
}
catch (BridgesmithException)
{
    if (driftHandler.PostCount != 0) throw new Exception("identity drift reached the operation route");
}

using var refusedRequest = new HttpRequestMessage(HttpMethod.Post, new Uri(baseUri, "op/get_api_events"))
{
    Content = JsonContent.Create(new Dictionary<string, object?>()),
};
refusedRequest.Headers.Add("x-bridgesmith-key", "proof-key");
using var refused = await http.SendAsync(refusedRequest);
if ((int)refused.StatusCode != 404) throw new Exception($"uncertified REST operation returned {(int)refused.StatusCode}, expected 404");
Console.WriteLine("dotnet-proof: certified-call=ok identity-drift=refused-before-post uncertified-surface=absent rest-refusal=404");

sealed class DriftedManifestHandler : HttpMessageHandler
{
    public int PostCount { get; private set; }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.Method == HttpMethod.Post) PostCount++;
        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = JsonContent.Create(new
            {
                app = EventsClient.CertifiedApp,
                version = EventsClient.CertificateVersion + 1,
                specHash = EventsClient.CertifiedSpecHash,
                certifiedOps = new[] { "get_api_events_event_id" },
            }),
        });
    }
}
`);

  const dotnet = process.env.DOTNET ?? "dotnet";
  const env = { DOTNET_CLI_TELEMETRY_OPTOUT: "1", DOTNET_NOLOGO: "1" };
  const built = await execa(dotnet, ["build", "--nologo", "--verbosity", "minimal"], { cwd: proofDir, env });
  process.stdout.write(built.stdout + "\n");
  const ran = await execa(dotnet, ["run", "--no-build", "--no-restore"], { cwd: proofDir, env });
  process.stdout.write(ran.stdout + "\n");
} finally {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  rmSync(root, { recursive: true, force: true });
}
