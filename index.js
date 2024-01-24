const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs')
const github = require('@actions/github')
const path = require('path');
const performance = require('perf_hooks').performance;
const process = require('process');

const toolVersion = "3.0.0";
const dottedQuadToolVersion = "3.0.0.0";

const cliScannerVersion = "1.8.0"
const cliScannerName = "sysdig-cli-scanner"
const cliScannerURL = `https://download.sysdig.com/scanning/bin/sysdig-cli-scanner/${cliScannerVersion}/linux/amd64/${cliScannerName}`
const cliScannerResult = "scan-result.json"

const defaultSecureEndpoint = "https://secure.sysdig.com/"
//const secureInlineScanImage = "quay.io/sysdig/secure-inline-scan:2"; // Hay que bajar el binario en vez de la imagen

// Sysdig to SARIF severity convertion
const LEVELS = {
  "error": ["High","Critical"],
  "warning": ["Medium"],
  "note": ["Negligible","Low"]
}

const EVALUATION = {
  "failed": "❌",
  "passed": "✅" 
}

class ExecutionError extends Error {
  constructor(stdout, stderr) {
    super("execution error\n\nstdout: " + stdout + "\n\nstderr: " + stderr);
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

function parseActionInputs() {
  return {
    cliScannerURL: core.getInput('cli-scanner-url') || cliScannerURL,
    registryUser: core.getInput('registry-user'),
    registryPassword: core.getInput('registry-password'),
    stopOnFailedPolicyEval: core.getInput('stop-on-failed-policy-eval') == 'true',
    stopOnProcessingError: core.getInput('stop-on-processing-error') == 'true',
    dbPath: core.getInput('db-path'),
    skipUpload: core.getInput('skip-upload') == 'true',
    usePolicies: core.getInput('use-policies'),
    overridePullString: core.getInput('override-pullstring'),
    imageTag: core.getInput('image-tag', { required: true }),
    sysdigSecureToken: core.getInput('sysdig-secure-token', { required: true }),
    sysdigSecureURL: core.getInput('sysdig-secure-url') || defaultSecureEndpoint,
    sysdigSkipTLS: core.getInput('sysdig-skip-tls') == 'true',
    extraParameters: core.getInput('extra-parameters'),
  }
}


function printOptions(opts) {
  if (opts.sysdigSecureURL) {
    core.info('Sysdig Secure URL: ' + opts.sysdigSecureURL);
  }

  if (opts.registryUser && opts.registryPassword) {
    core.info(`Using specified Registry credentials.`);
  }

  core.info(`Stop on Failed Policy Evaluation: ${opts.stopOnFailedPolicyEval}`);

  core.info(`Stop on Processing Error: ${opts.stopOnProcessingError}`);

  if (opts.skipUpload) {
    core.info(`Skipping scan results upload to Sysdig Secure...`);
  }

  if (opts.dbPath) {
    core.info(`DB Path: ${opts.dbPath}`);
  }

  core.info(`Sysdig skip TLS: ${opts.sysdigSkipTLS}`);

  if (opts.severity) {
    core.info(`Severity level: ${opts.severity}`);
  }

  core.info('Analyzing image: ' + opts.imageTag);

  if (opts.overridePullString) {
    core.info(` * Image PullString will be overwritten as ${opts.overridePullString}`);
  }
}

function composeFlags(opts) {
  let envvars = {}
  envvars['SECURE_API_TOKEN'] = opts.sysdigSecureToken || "";

  let flags = ` --json-scan-result=${cliScannerResult}`;

  if (opts.registryUser) {
    envvars['REGISTRY_USER'] = opts.registryUser;
  }

  if (opts.registryPassword) {
    envvars['REGISTRY_PASSWORD'] = opts.registryPassword;
  }

  if (opts.sysdigSecureURL) {
    flags += ` --apiurl ${opts.sysdigSecureURL}`;
  }

  if (opts.dbPath) {
    flags += ` --dbpath=${opts.dbPath}`;
  }

  if (opts.skipUpload) {
    flags += ' --skipupload';
  }

  if (opts.usePolicies) {
    flags += ` --policy=${opts.usePolicies}`;
  }

  if (opts.sysdigSkipTLS) {
    flags += ` --skiptlsverify`;
  }

  if (opts.overridePullString) {
    flags += ` --override-pullstring=${opts.overridePullString}`;
  }

  if (opts.extraParameters) {
    flags += ` ${opts.extraParameters}`;
  }

  flags += ` ${opts.imageTag || ""}`;

  return {
    envvars: envvars,
    flags: flags
  }
}

function writeReport(reportData) {
  fs.writeFileSync("./report.json", reportData);
  core.setOutput("scanReport", "./report.json");
}

async function run() {

  try {
    let opts = parseActionInputs();
    printOptions(opts);
    let scanFlags = composeFlags(opts);

    await pullScanner(opts.cliScannerURL);
    let scanResult = await executeScan(scanFlags.envvars, scanFlags.flags);

    if (scanResult.ReturnCode == 0 || scanResult.ReturnCode == 1) {
      await processScanResult(scanResult, opts);
    }

    if (opts.stopOnFailedPolicyEval && scanResult.ReturnCode == 1) {
      core.setFailed(`Stopping because Policy Evaluation was FAILED.`);
    } else if (scanResult.ReturnCode == 0) {
      core.info("Policy Evaluation was PASSED.");
    } else if (opts.stopOnProcessingError) {
      core.setFailed(`Stopping because the scanner terminated with an error.`);
    } // else: Don't stop regardless the outcome.

  } catch (error) {
    if (core.getInput('stop-on-processing-error') == 'true') {
      core.setFailed("Unexpected error");
    }
    core.error(error);
  }
}

async function processScanResult(result, opts) {
  let scanResult;
  if (result.ReturnCode == 0) {
    scanResult = "Success";
    core.info(`Scan was SUCCESS.`);
  } else if (result.ReturnCode == 1) {
    scanResult = "Failed";
    core.info(`Scan was FAILED.`);
  } else if (result.ReturnCode == 2) {
    core.setFailed("Invalid Parameters");
    throw new ExecutionError(result.Output, result.Error);
  } else {
    core.setFailed("Execution error");
    throw new ExecutionError(result.Output, result.Error);
  }

  writeReport(result.Output);

  let report;
  try {
    report = JSON.parse(result.Output);
  } catch (error) {
    core.error("Error parsing analysis JSON report: " + error + ". Output was: " + result.output);
    throw new ExecutionError(result.Output, result.Error);
  }

  if (report) {

    let tag = "";
    try {
      tag = report.result.metadata.pullString;
    } catch (error) {
      core.error("Error parsing results report: " + error);
    }

    generateSARIFReport(report);
    await generateSummary(tag, scanResult, report);
  }
}

async function pullScanner(scannerURL) {
  let start = performance.now();
  core.info('Pulling cli-scanner from: ' + scannerURL);
  let cmd = `wget ${scannerURL} -O ./${cliScannerName}`;
  await exec.exec(cmd, null, {silent: true});

  cmd = `chmod u+x ./${cliScannerName}`;
  await exec.exec(cmd, null, {silent: true});
  core.info("Scanner pull took " + Math.round(performance.now() - start) + " milliseconds.");
}

async function executeScan(envvars, flags) {

  let execOutput = '';
  let errOutput = '';


  const scanOptions = {
    env: envvars,
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data) => {
        process.stdout.write(data);
      },
      stderr: (data) => {
        process.stderr.write(data);
      }
    }
  };

  const catOptions = {
    silent: true,
    ignoreReturnCode: true,
    listeners: {
      stdout: (data) => {
        execOutput += data.toString();
      },
      stderr: (data) => {
        errOutput += data.toString();
      }
    }
  }

  let start = performance.now();
  let cmd = `./${cliScannerName} ${flags}`;
  core.debug("Executing: " + cmd);
  let retCode = await exec.exec(cmd, null, scanOptions);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  if (retCode == 0 || retCode == 1) {
    cmd = `cat ./${cliScannerResult}`;
    await exec.exec(cmd, null, catOptions);
  }
  return { ReturnCode: retCode, Output: execOutput, Error: errOutput };
}

function vulnerabilities2SARIF(data) {
  const [rules, results] = vulnerabilities2SARIFRes(data)

  const runs = [{
    tool: {
      driver: {
        name: "sysdig-cli-scanner",
        fullName: "Sysdig Vulnerability CLI Scanner",
        informationUri: "https://docs.sysdig.com/en/docs/installation/sysdig-secure/install-vulnerability-cli-scanner",
        version: toolVersion,
        semanticVersion: toolVersion,
        dottedQuadFileVersion: dottedQuadToolVersion,
        rules: rules //vulnerabilities2SARIFRules(data)
      }
    },
    logicalLocations: [
      {
        name: "container-image",
        fullyQualifiedName: "container-image",
        kind: "namespace"
      }
    ],
    results: results, //vulnerabilities2SARIFResults(data),
    columnKind: "utf16CodeUnits",
    properties: {
      pullString: data.result.metadata.pullString,
      digest: data.result.metadata.digest,
      imageId: data.result.metadata.imageId,
      architecture: data.result.metadata.architecture,
      baseOs: data.result.metadata.baseOs,
      os: data.result.metadata.os,
      size: data.result.metadata.size,
      layersCount: data.result.metadata.layersCount,
      resultUrl: data.info.resultUrl || "",
      resultId: data.info.resultId || "",
  }
  }];


  const sarifOutput = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: runs
  };

  return (sarifOutput);
}

function check_level(sev_value) {
  let level = "note";

  for (let key in LEVELS) {
    if (sev_value in LEVELS[key]) {
      level = key
    }
  }

  return level
}

function vulnerabilities2SARIFRes(data) {
  let results = [];
  let rules = [];
  let ruleIds = [];
  let resultUrl = "";
  let baseUrl = null;
  
  if (data.info.resultUrl) {
    resultUrl = data.info.resultUrl;
    baseUrl = resultUrl.slice(0,resultUrl.lastIndexOf('/'));
  }

  data.result.packages.forEach(function (pkg, index) {
    if (!pkg.vulns) {
      return
    }

    pkg.vulns.forEach(function (vuln, index) {
      if (!(vuln.name in ruleIds)){
        ruleIds.push(vuln.name)
        rule = {
          id: vuln.name,
          name: pkg.type,
          shortDescription: {
            text: getSARIFVulnShortDescription(pkg, vuln)
          },
          fullDescription: {
            text: getSARIFVulnFullDescription(pkg, vuln)
          },
          helpUri: `https://nvd.nist.gov/vuln/detail/${vuln.name}`,
          help: getSARIFVulnHelp(pkg, vuln),
          properties: {
            precision: "very-high",
            'security-severity': `${vuln.cvssScore.value.score}`,
            tags: [
                'vulnerability',
                'security',
                vuln.severity.value
            ]
          }
        }
        rules.push(rule)
      }

      result = {
        ruleId: vuln.name,
        level: check_level(vuln.severity.value),
        message: {
          text: getSARIFReportMessage(data, vuln, pkg, baseUrl)
        },
        locations: [
          {
              physicalLocation: {
                  artifactLocation: {
                      uri: data.result.metadata.pullString,
                      uriBaseId: "ROOTPATH"
                  }
              },
              message: {
                  text: `${data.result.metadata.pullString} - ${pkg.name}@${pkg.version}`
              }
          }
        ]
      }
      results.push(result)
    });
  });
  
  return [rules, results];
}

function getSARIFVulnShortDescription(pkg, vuln) {
  return `${vuln.name} Severity: ${vuln.severity.value} Package: ${pkg.name}`;
}

function getSARIFVulnFullDescription(pkg, vuln) {
  return `${vuln.name}
Severity: ${vuln.severity.value}
Package: ${pkg.name}
Type: ${pkg.type}
Fix: ${pkg.suggestedFix || "Unknown"}
URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`;
}

function getSARIFVulnHelp(pkg, vuln) {
  return {
    text: `Vulnerability ${vuln.name}
Severity: ${vuln.severity.value}
Package: ${pkg.name}
CVSS Score: ${vuln.cvssScore.value.score}
CVSS Version: ${vuln.cvssScore.value.version}
CVSS Vector: ${vuln.cvssScore.value.vector}
Version: ${pkg.version}
Fix Version: ${pkg.suggestedFix || "Unknown"}
Exploitable: ${vuln.exploitable}
Type: ${pkg.type}
Location: ${pkg.path}
URL: https://nvd.nist.gov/vuln/detail/${vuln.name}`,
    markdown: `
**Vulnerability [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})**
| Severity | Package | CVSS Score | CVSS Version | CVSS Vector | Fixed Version | Exploitable |
| -------- | ------- | ---------- | ------------ | ----------- | ------------- | ----------- |
| ${vuln.severity.value} | ${pkg.name} | ${vuln.cvssScore.value.score} | ${vuln.cvssScore.value.version} | ${vuln.cvssScore.value.vector} | ${pkg.suggestedFix || "None"} | ${vuln.exploitable} |`
  }
}

function getSARIFReportMessage(data, vuln, pkg, baseUrl) {
  let message = `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})`;

  if (baseUrl) message += `Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+(\"${pkg.name}\"))`;
  
  message += `Package type: ${pkg.type}
  Installed Version: ${pkg.version}
  Package path: ${pkg.path}`;

  if (baseUrl) message += `Vulnerability: [${vuln.name}](${baseUrl}/vulnerabilities?filter=freeText+in+(\"${vuln.name}\"))`;
  
  message += `Severity: ${vuln.severity.value}
  CVSS Score: ${vuln.cvssScore.value.score}
  CVSS Version: ${vuln.cvssScore.value.version}
  CVSS Vector: ${vuln.cvssScore.value.vector}
  Fixed Version: ${(vuln.fixedInVersion || 'Unknown')}
  Exploitable: ${vuln.exploitable}
  Link to NVD: [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})`;
  
  return message;
}

function getRuleId(v) {
  return "VULN_" + v.vuln + "_" + v.package_type + "_" + v.package;
}

function generateSARIFReport(data) {
  let sarifOutput = vulnerabilities2SARIF(data);
  core.setOutput("sarifReport", "./sarif.json");
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
}

async function generateSummary(tag, scanResult, data) {
  // const githubToken = core.getInput('github-token');
  // if (!githubToken) {
  //   core.warning("No github-token provided. Skipping creation of check run");
  // }

  // let octokit;
  // let annotations;
  // let check_run;

  // try {
  //   octokit = github.getOctokit(githubToken);
  // } catch (error) {
  //   core.warning("Error creating octokit: " + error);
  //   return;
  // }



  core.summary
  .addHeading('Scan Results')
  .addRaw(`Policies evaluation: ${data.result.policyEvaluationsResult} ${EVALUATION[data.result.policyEvaluationsResult]}`);
  
  addVulnTableToSummary(data);
  addReportToSummary(data);

  await core.summary.write();

  // let conclusion = "success";
  // if (scanResult != "Success") {
  //   conclusion = "failure";
  // }

  // try {
  //   check_run = await octokit.rest.checks.create({
  //     owner: github.context.repo.owner,
  //     repo: github.context.repo.repo,
  //     name: `Scan results for ${tag}`,
  //     head_sha: github.context.sha,
  //     status: "completed",
  //     conclusion:  conclusion,
  //     output: {
  //       title: `Inline scan results for ${tag}`,
  //       summary: "Scan result is " + scanResult,
  //       annotations: annotations.slice(0,50)
  //     }
  //   });
  // } catch (error) {
  //   core.warning("Error creating check run: " + error);
  // }

  // try {
  //   for (let i = 50; i < annotations.length; i+=50) {
  //     await octokit.rest.checks.update({
  //       owner: github.context.repo.owner,
  //       repo: github.context.repo.repo,
  //       check_run_id: check_run.data.id,
  //       output: {
  //         title: "Inline scan results",
  //         summary: "Scan result is " + scanResult,
  //         annotations: annotations.slice(i, i+50)
  //       }
  //     });
  //   }
  // } catch (error) {
  //   core.warning("Error updating check run: " + error);
  // }
}

function getRulePkgMessage(rule, packages) {
  let table = [[ 
    {data: 'Severity', header: true},
    {data: 'Package', header: true},
    {data: 'CVSS Score', header: true},
    {data: 'CVSS Version', header: true},
    {data: 'CVSS Vector', header: true},
    {data: 'Fixed Version', header: true},
    {data: 'Exploitable', header: true}]];

  rule.failures.forEach(failure => {
    let pkgIndex = failure.pkgIndex;
    let vulnInPkgIndex = failure.vulnInPkgIndex;

    let pkg = packages[pkgIndex];
    let vuln = pkg.vulns[vulnInPkgIndex];
    table.push([`${vuln.severity.value}`,
      `${pkg.name}`,
      `${vuln.cvssScore.value.score}`,
      `${vuln.cvssScore.value.version}`,
      `${vuln.cvssScore.value.vector}`,
      `${pkg.suggestedFix || "Unknown"}`,
      `${vuln.exploitable}`
    ]);
  });

  core.summary.addTable(table);
}

function getRuleImageMessage(rule) {
  let message = [];

  rule.failures.forEach(failure => {
    message.push(`${failure.remediation}`)
  });

  core.summary.addList(message);
}

function addVulnTableToSummary(data) {
  let totalVuln = data.result.vulnTotalBySeverity;
  let fixableVuln = data.result.fixableVulnTotalBySeverity;

  core.summary.addBreak;
  core.summary.addTable([
    [{data: '', header: true}, {data: '🟣 Critical', header: true}, {data: '🔴 High', header: true}, {data: '🟠 Medium', header: true}, {data: '🟡 Low', header: true}, {data: '⚪ Negligible', header: true}],
    [{data: '⚠️ Total Vulnerabilities', header: true}, `${totalVuln.critical}`, `${totalVuln.high}`, `${totalVuln.medium}`, `${totalVuln.low}`, `${totalVuln.negligible}`],
    [{data: '🔧 Fixable Vulnerabilities', header: true}, `${fixableVuln.critical}`, `${fixableVuln.high}`, `${fixableVuln.medium}`, `${fixableVuln.low}`, `${fixableVuln.negligible}`],
  ]);
}

function addReportToSummary(data) {
  let policyEvaluations = data.result.policyEvaluations;
  let packages = data.result.packages;

  policyEvaluations.forEach(policy => {
    core.summary.addHeading(`${EVALUATION[policy.evaluationResult]} Policy: ${policy.name}`,2)

    if (policy.evaluationResult != "passed") {
      policy.bundles.forEach(bundle => {
        core.summary.addHeading(`Rule Bundle: ${bundle.name}`,3)

        bundle.rules.forEach(rule => {
          core.summary.addHeading(`${EVALUATION[rule.evaluationResult]} Rule: ${rule.description}`,5)

          if (rule.evaluationResult != "passed") {
            if (rule.failureType == "pkgVulnFailure") {
              getRulePkgMessage(rule, packages)
            } else {
              getRuleImageMessage(rule)
            }
          }
          core.summary.addBreak()
        });
      });
    }
  });
}

module.exports = {
  ExecutionError,
  parseActionInputs,
  composeFlags,
  pullScanner,
  executeScan,
  processScanResult,
  run
};

if (require.main === module) {
  run();
}
