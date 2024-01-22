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

class ExecutionError extends Error {
  constructor(stdout, stderr) {
    super("execution error\n\nstdout: " + stdout + "\n\nstderr: " + stderr);
    this.stdout = stdout;
    this.stderr = stderr;
  }
}

function parseActionInputs() {
  return {
    cliScannerURL: core.getInput('cli-scanner-url') || cliScannerURL, // @TBA
    registryUser: core.getInput('registry-user'),
    registryPassword: core.getInput('registry-password'),

    // Legacy Inputs vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
    imageTag: core.getInput('image-tag', { required: true }),
    sysdigSecureToken: core.getInput('sysdig-secure-token', { required: true }),
    sysdigSecureURL: core.getInput('sysdig-secure-url') || defaultSecureEndpoint,
    sysdigSkipTLS: core.getInput('sysdig-skip-tls') == 'true',
    // dockerfilePath: core.getInput('dockerfile-path'),
    ignoreFailedScan: core.getInput('ignore-failed-scan') == 'true',
    // inputType: core.getInput('input-type'),
    // inputPath: core.getInput('input-path'),
    //runAsUser: core.getInput('run-as-user'),
    extraParameters: core.getInput('extra-parameters'),

    // extraDockerParameters: core.getInput('extra-docker-parameters'),
    // inlineScanImage: core.getInput('inline-scan-image'),
  }
}


function printOptions(opts) {
  if (opts.sysdigSecureURL) {
    core.info('Sysdig Secure URL: ' + opts.sysdigSecureURL);
  }

  // if (opts.inputType == "pull") {
  //   core.info('Input type: pull from registry');
  // } else {
  //   core.info(`Input type: ${opts.inputType}`);
  // }

  // if (opts.inputPath) {
  //   core.info(`Input path: ${opts.inputPath}`);
  // }

  // if (opts.dockerfilePath) {
  //   core.info(`Dockerfile Path: ${opts.dockerfilePath}`);
  // }

  if (opts.sysdigSkipTLS) {
    core.info(`Sysdig skip TLS: true`);
  }

  if (opts.severity) {
    core.info(`Severity level: ${opts.severity}`);
  }

  core.info('Analyzing image: ' + opts.imageTag);
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

  // if (opts.inputType != "pull") {
  //   flags += ` --storage-type=${opts.inputType}`;

  //   if (opts.inputType == "docker-daemon") {
  //     let dockerSocketPath = opts.inputPath || "/var/run/docker.sock";
  //     dockerFlags += ` -v ${dockerSocketPath}:/var/run/docker.sock`;
  //   } else if (opts.inputPath) {
  //     let filename = path.basename(opts.inputPath);
  //     dockerFlags += ` -v ${path.resolve(opts.inputPath)}:/tmp/${filename}`;
  //     flags += ` --storage-path=/tmp/${filename}`;
  //   }
  // }

  // if (opts.dockerfilePath) {
  //   flags += ` --dockerfile=/tmp/Dockerfile`;
  // }

  if (opts.sysdigSkipTLS) {
    flags += ` --skiptlsverify`;
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
    // exit(0);  // <-- Implemented 'til here

    let success = await processScanResult(scanResult);
    if (!(success || opts.ignoreFailedScan)) {
      core.setFailed(`Scan was FAILED.`)
    }

  } catch (error) {
    core.setFailed("Unexpected error");
    core.error(error);
  }
}

async function processScanResult(result) {
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

    let evaluationResults;
    if (report.scanReport) {
      try {
        let digest = report.result.metadata.digest;
        let tag = report.result.metadata.pullString;
        let imageId = report.result.metadata.imageId;
        evaluationResults = report.scanReport[0][digest][tag][0].detail.result.result[imageId].result;
      } catch (error) {
        core.error("Error parsing results report: " + error);
      }
    }

    generateSARIFReport(report);
    //await generateChecks(tag, scanResult, evaluationResults, vulnerabilities);
  }

  return result.ReturnCode == 0;
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
    //silent: true,
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


  //let retCode = await exec.exec(`docker run -d --entrypoint /bin/cat -ti ${dockerFlags} ${scanImage}`, null, scanOptions);
  let start = performance.now();
  let cmd = `./${cliScannerName} ${flags}`;
  core.debug("Executing: " + cmd);
  let retCode = await exec.exec(cmd, null, scanOptions);
  core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  // if (retCode != 0) {
  //   return { ReturnCode: -1, Output: execOutput, Error: errOutput };
  // }

  cmd = `cat ./${cliScannerResult}`;
  retCode = await exec.exec(cmd, null, catOptions);

  // let containerId = execOutput.trim();
  // await exec.exec(`docker exec ${containerId} mkdir -p /tmp/sysdig-inline-scan/logs/`, null, {silent: true, ignoreReturnCode: true});
  // await exec.exec(`docker exec ${containerId} touch /tmp/sysdig-inline-scan/logs/info.log`, null, {silent: true, ignoreReturnCode: true});
  // let tailExec = exec.exec(`docker exec ${containerId} tail -f /tmp/sysdig-inline-scan/logs/info.log`, null, tailOptions);

  // execOutput = '';
  // let start = performance.now();
  // let cmd = `docker exec ${containerId} /sysdig-inline-scan.sh ${runFlags}`;
  // core.debug("Executing: " + cmd);
  // retCode = await exec.exec(cmd, null, scanOptions);
  // core.info("Image analysis took " + Math.round(performance.now() - start) + " milliseconds.");

  // await function () {
  //   return new Promise((resolve) => {
  //     setTimeout(resolve, 1000);
  //   });
  // }();

  // try {
  //   await exec.exec(`docker stop ${containerId} -t 0`, null, {silent: true, ignoreReturnCode: true});
  //   await exec.exec(`docker rm ${containerId}`, null, {silent: true, ignoreReturnCode: true});
  //   await tailExec;
  // } catch (error) {
  //   core.info("Error stopping container: " + error);
  // }

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
      resultUrl: data.info.resultUrl,
      resultId: data.info.resultId,
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
  let results = []
  let rules = []
  let ruleIds = []
  let resultUrl = data.info.resultUrl;
  let baseUrl = resultUrl.slice(0,resultUrl.lastIndexOf('/'));

  data.result.packages.forEach(function (pkg, index) {
    if (!pkg.vulns) {
      //LOG.info(f"Package: {pkg.name} has no vulnerabilities...skipping...")
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
            'security-severity': vuln.cvssScore.value.score,
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

function vulnerabilities2SARIFRules(data) {
  var ret = {};
  if (data) {
    ret = data.map(v => {
      return {
        id: getRuleId(v),
        shortDescription: {
          text: getSARIFVulnShortDescription(v),
        },
        fullDescription: {
          text: getSARIFVulnFullDescription(v),
        },
        help: getSARIFVulnHelp(v)
      }
    }
    );
  }
  return (ret);
}

function vulnerabilities2SARIFResults(tag, vulnerabilities) {
  var ret = {};

  if (vulnerabilities) {
    ret = vulnerabilities.map((v) => {
      return {
        ruleId: getRuleId(v),
        ruleIndex: 0,
        level: "error",
        message: {
          text: getSARIFVulnShortDescription(v),
          id: "default",
        },
        analysisTarget: {
          uri: `Container image ${tag}`,
          index: 0,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: `Container image ${tag}`,
              },
              region: {
                startLine: 1,
                startColumn: 1,
                endLine: 1,
                endColumn: 1,
                byteOffset: 1,
                byteLength: 1,
              },
            },
            logicalLocations: [
              {
                fullyQualifiedName: `Container image ${tag}`,
              },
            ],
          },
        ],
        suppressions: [
          {
            kind: "external",
          },
        ],
        baselineState: "unchanged",
      };
    });
  }
  return ret;
}


function getSARIFVulnShortDescription(pkg, vuln) {
  return `${vuln.name} Severity: ${vuln.severity.value} Package: ${pkg.name}`;
}

function getSARIFVulnFullDescription(pkg, vuln) {
  return `${vuln.name}
Severity: ${vuln.severity.value}
Package: ${pkg.name}
Type: ${pkg.type}
Fix: ${pkg.suggestedFix || "None"}
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
Fix Version: ${pkg.suggestedFix || "None"}
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
  return `Full image scan results in Sysdig UI: [${data.result.metadata.pullString} scan result](${data.info.resultUrl})
  Package: [${pkg.name}](${baseUrl}/content?filter=freeText+in+(${pkg.name}\))
  Package type: ${pkg.type}
  Installed Version: ${pkg.version}
  Package path: ${pkg.path}
  Vulnerability: [${vuln.name}](${baseUrl}/vulnerabilities?filter=freeText+in+(${vuln.name}\))
  Severity: ${vuln.severity.value}
  CVSS Score: ${vuln.cvssScore.value.score}
  CVSS Version: ${vuln.cvssScore.value.version}
  CVSS Vector: ${vuln.cvssScore.value.vector}
  Fixed Version: ${(vuln.fixedInVersion || 'None')}
  Exploitable: ${vuln.exploitable}
  Link to NVD: [${vuln.name}](https://nvd.nist.gov/vuln/detail/${vuln.name})`
  ;
}

function getRuleId(v) {
  return "VULN_" + v.vuln + "_" + v.package_type + "_" + v.package;
}

function generateSARIFReport(data) {
  let sarifOutput = vulnerabilities2SARIF(data);
  core.setOutput("sarifReport", "./sarif.json");
  fs.writeFileSync("./sarif.json", JSON.stringify(sarifOutput, null, 2));
}

async function generateChecks(tag, scanResult, evaluationResults, vulnerabilities) {
  const githubToken = core.getInput('github-token');
  if (!githubToken) {
    core.warning("No github-token provided. Skipping creation of check run");
  }

  let octokit;
  let annotations;
  let check_run;

  try {
    octokit = github.getOctokit(githubToken);
    annotations = getReportAnnotations(evaluationResults, vulnerabilities)
  } catch (error) {
    core.warning("Error creating octokit: " + error);
    return;
  }

  let conclusion = "success";
  if (scanResult != "Success") {
    conclusion = "failure";
  }

  try {
    check_run = await octokit.rest.checks.create({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      name: `Scan results for ${tag}`,
      head_sha: github.context.sha,
      status: "completed",
      conclusion:  conclusion,
      output: {
        title: `Inline scan results for ${tag}`,
        summary: "Scan result is " + scanResult,
        annotations: annotations.slice(0,50)
      }
    });
  } catch (error) {
    core.warning("Error creating check run: " + error);
  }

  try {
    for (let i = 50; i < annotations.length; i+=50) {
      await octokit.rest.checks.update({
        owner: github.context.repo.owner,
        repo: github.context.repo.repo,
        check_run_id: check_run.data.id,
        output: {
          title: "Inline scan results",
          summary: "Scan result is " + scanResult,
          annotations: annotations.slice(i, i+50)
        }
      });
    }
  } catch (error) {
    core.warning("Error updating check run: " + error);
  }
}

function getReportAnnotations(evaluationResults, vulnerabilities) {
  let actionCol = evaluationResults.header.indexOf("Gate_Action");
  let gateCol = evaluationResults.header.indexOf("Gate");
  let triggerCol = evaluationResults.header.indexOf("Trigger");
  let outputCol = evaluationResults.header.indexOf("Check_Output");
  let gates = evaluationResults.rows.map(g => {
    let action = g[actionCol];
    let level = "notice"
    if (action == "warn") {
      level = "warning";
    } else if (action == "stop") {
      level = "failure";
    }
    return {
      path: "Dockerfile",
      start_line: 1,
      end_line: 1,
      annotation_level: level,
      message: `${g[actionCol]} ${g[gateCol]}:${g[triggerCol]}\n${g[outputCol]}`,
      title: `${g[actionCol]} ${g[gateCol]}`
    }
  });
  let severities = {"critical":0,"high":1, "medium":2, "low":3, "negligible":4,"unknown":5}
  let severity =  core.getInput('severity') || "unknown";
  let uniqueReportByPackage = core.getInput('unique-report-by-package') === 'true' || false;
  let _vulns = vulnerabilities
  if(uniqueReportByPackage) {
    const key = 'package'; // Show only one issue by pkg, avoiding flood of annotations
    let _sortedVulns = _vulns.sort((a, b) => severities[b.severity.toLowerCase()] - severities[a.severity.toLowerCase()]);
    _vulns = [...new Map(_sortedVulns.map(item => [item[key], item])).values()];
  }
  let vulns = _vulns.filter(v => severities[v.severity.toLowerCase()] <=  severities[severity.toLowerCase()]).map(v => {
    return {
      path: "Dockerfile",
      start_line: 1,
      end_line: 1,
      annotation_level: "warning", //Convert v.severity to notice, warning, or failure?
      message: `${v.vuln} Severity=${v.severity} Package=${v.package} Type=${v.package_type} Fix=${v.fix} Url=${v.url}`,
      title: `Vulnerability found: ${v.vuln}`
    }
  });
  return gates.concat(vulns);
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
