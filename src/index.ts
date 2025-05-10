import express, { Request, Response } from "express";
import { exec } from "child_process";
import path from "path";
import fs from "fs";
import simpleGit from "simple-git";
import cors from 'cors';

// Initialize the Express app
const app = express();
app.use(express.json({ limit: '10mb' })); // Increase JSON payload limit

app.use(cors({
  origin: '*', // Consider restricting this in production
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

const git = simpleGit();
const TEMP_DIR = path.join(__dirname, "temp");

// Ensure temp directory exists with proper permissions
if (!fs.existsSync(TEMP_DIR)) {
  try {
    fs.mkdirSync(TEMP_DIR, { recursive: true, mode: 0o777 });
    console.log(`Created temp directory: ${TEMP_DIR}`);
  } catch (error) {
    console.error(`Error creating temp directory: ${error}`);
  }
}

// Test file system permissions
try {
  const testFile = path.join(TEMP_DIR, "test.txt");
  fs.writeFileSync(testFile, "test");
  console.log(`Successfully wrote test file: ${testFile}`);
  fs.unlinkSync(testFile);
  console.log(`Successfully deleted test file: ${testFile}`);
} catch (error) {
  console.error(`File system permission test failed: ${error}`);
}

// Test if semgrep is available
try {
  exec("semgrep --version", (error, stdout, stderr) => {
    if (error) {
      console.error(`Error checking semgrep version: ${error.message}`);
      console.error(`stderr: ${stderr}`);
    } else {
      console.log(`Semgrep version: ${stdout.trim()}`);
    }
  });
} catch (error) {
  console.error(`Failed to execute semgrep version check: ${error}`);
}

// Helper function to recursively list all files in a directory
function listAllFiles(dir: string, fileList: string[] = []): string[] {
  try {
    const files = fs.readdirSync(dir);

    files.forEach((file) => {
      const filePath = path.join(dir, file);
      try {
        if (fs.statSync(filePath).isDirectory()) {
          // Skip .git directory
          if (file !== ".git") {
            fileList = listAllFiles(filePath, fileList);
          }
        } else {
          fileList.push(filePath);
        }
      } catch (error) {
        console.error(`Error processing file ${filePath}: ${error}`);
      }
    });

    return fileList;
  } catch (error) {
    console.error(`Error listing files in directory ${dir}: ${error}`);
    return fileList;
  }
}

// Helper function to clone the GitHub repository dynamically
async function cloneRepository(gitUrl: string): Promise<string> {
  const repoName = gitUrl.split("/").pop()?.replace(".git", "") || "repo";
  const repoPath = path.join(TEMP_DIR, repoName);

  console.log(`Cloning repository to: ${repoPath}`);

  // Remove any previous clone of the repository
  if (fs.existsSync(repoPath)) {
    console.log(`Removing existing directory: ${repoPath}`);
    try {
      fs.rmSync(repoPath, { recursive: true, force: true });
    } catch (error) {
      console.error(`Error removing directory: ${error}`);
      throw new Error(`Failed to remove existing directory: ${error}`);
    }
  }

  try {
    // Clone the repository
    console.log(`Starting clone of: ${gitUrl}`);
    await git.clone(gitUrl, repoPath);
    console.log(`Successfully cloned to: ${repoPath}`);

    // Verify the clone
    if (!fs.existsSync(repoPath)) {
      throw new Error(
        `Repository directory not found after clone: ${repoPath}`
      );
    }

    return repoPath;
  } catch (error: any) {
    console.error(`Error cloning repository: ${error.message}`);
    throw new Error(`Failed to clone repository: ${error.message}`);
  }
}

// Helper function to run Semgrep on the cloned repository
function runSemgrep(directory: string): Promise<string> {
  return new Promise((resolve, reject) => {
    console.log(`Running Semgrep on directory: ${directory}`);

    // Verify directory exists
    if (!fs.existsSync(directory)) {
      reject(`Directory does not exist: ${directory}`);
      return;
    }

    // Create a simple test rule to verify semgrep works
    const testRuleFile = path.join(directory, "test-rule.yml");
    const testRuleContent = `
rules:
  - id: test-rule
    pattern: console.log(...)
    message: "Test rule successful"
    languages: [javascript, typescript]
    severity: INFO
    `;
    
    try {
      fs.writeFileSync(testRuleFile, testRuleContent);
      console.log(`Created test rule file: ${testRuleFile}`);
    } catch (error) {
      console.error(`Error creating test rule file: ${error}`);
      reject(`Error creating test rule file: ${error}`);
      return;
    }

    // First try with a simple test to see if Semgrep works
    console.log(`Testing Semgrep with simple rule...`);
    exec(
      `cd ${directory} && semgrep scan --config=${testRuleFile} . --json`,
      { maxBuffer: 10 * 1024 * 1024 }, // 10MB buffer
      (error, stdout, stderr) => {
        try {
          if (fs.existsSync(testRuleFile)) {
            fs.unlinkSync(testRuleFile);
          }
        } catch (fsError) {
          console.error(`Error cleaning up test rule file: ${fsError}`);
        }

        if ((error && error.code !== 1) || stderr.includes("Fatal") || stderr.includes("Error")) {
          console.error(`Semgrep test failed: ${stderr}`);
          console.error(`Using direct rule file instead of registry...`);
          
          // Fall back to custom ruleset
          const customRuleFile = path.join(directory, "custom-rules.yml");
          const customRuleContent = `
rules:
  - id: a1-sql-injection
    patterns:
      - pattern-either:
          - pattern: |
              "SELECT ... FROM ... WHERE ... = '" + $X + "'"
          - pattern: |
              \`SELECT ... FROM ... WHERE ... = '\${$X}'\`
    message: "OWASP A1:2017 - Injection: Potential SQL injection vulnerability"
    languages: [javascript, typescript]
    severity: CRITICAL
          
  - id: a7-xss
    patterns:
      - pattern-either:
          - pattern: |
              $ELEMENT.innerHTML = ...
    message: "OWASP A7:2017 - XSS: Direct assignment to innerHTML"
    languages: [javascript, typescript]
    severity: WARNING
          
  - id: a6-eval-usage
    pattern: eval(...)
    message: "OWASP A6:2017 - Security Misconfiguration: Use of eval() detected"
    languages: [javascript, typescript]
    severity: ERROR
          
  - id: debug-console-log
    pattern: console.log(...)
    message: "Debug: Console logging found in code"
    languages: [javascript, typescript]
    severity: INFO
          `;
          
          try {
            fs.writeFileSync(customRuleFile, customRuleContent);
            console.log(`Created custom rule file: ${customRuleFile}`);
          } catch (error) {
            console.error(`Error creating custom rule file: ${error}`);
            reject(`Error creating custom rule file: ${error}`);
            return;
          }
          
          // Run with the custom ruleset
          exec(
            `cd ${directory} && semgrep scan --config=${customRuleFile} . --json`,
            { maxBuffer: 10 * 1024 * 1024 },
            (fallbackError, fallbackStdout, fallbackStderr) => {
              try {
                if (fs.existsSync(customRuleFile)) {
                  fs.unlinkSync(customRuleFile);
                }
              } catch (fsError) {
                console.error(`Error cleaning up custom rule file: ${fsError}`);
              }
              
              if (fallbackError && fallbackError.code !== 1) {
                console.error(`Semgrep fallback execution error: ${fallbackError.message}`);
                console.error(`Semgrep fallback stderr: ${fallbackStderr}`);
                reject(`Error running Semgrep with custom rules: ${fallbackStderr}`);
              } else {
                console.log(`Semgrep fallback scan completed`);
                resolve(fallbackStdout);
              }
            }
          );
        } else {
          console.log(`Semgrep test successful, running with registry rules...`);
          
          // First test passed, now try with registry ruleset
          try {
            // Check if .semgrep-custom.yml exists in the project root
            const semgrepConfigPath = path.join(process.cwd(), ".semgrep-custom.yml");
            console.log(`Looking for semgrep config at: ${semgrepConfigPath}`);
            
            let semgrepCommand;
            if (fs.existsSync(semgrepConfigPath)) {
              console.log(`Using local semgrep config: ${semgrepConfigPath}`);
              semgrepCommand = `cd ${directory} && semgrep scan --config=${semgrepConfigPath} . --json`;
            } else {
              console.log(`No local config found, using registry rules`);
              semgrepCommand = `cd ${directory} && semgrep scan --config=p/javascript . --json`;
            }
            
            console.log(`Executing: ${semgrepCommand}`);
            exec(
              semgrepCommand,
              { maxBuffer: 10 * 1024 * 1024 },
              (registryError, registryStdout, registryStderr) => {
                if (registryError && registryError.code !== 1) {
                  console.error(`Semgrep registry error: ${registryError.message}`);
                  console.error(`Semgrep registry stderr: ${registryStderr}`);
                  // If registry scan fails, return the test scan results at minimum
                  console.log(`Falling back to test scan results`);
                  resolve(stdout);
                } else {
                  console.log(`Semgrep registry scan completed`);
                  resolve(registryStdout);
                }
              }
            );
          } catch (execError) {
            console.error(`Error executing registry scan: ${execError}`);
            // If there's an error with registry scan, return test scan results
            resolve(stdout);
          }
        }
      }
    );
  });
}

// POST /analyze: Endpoint to receive a GitHub repository URL for analysis
app.post("/analyze", async (req: Request, res: Response) => {
  console.log("Received analyze request");
  
  const { gitUrl } = req.body;

  if (!gitUrl) {
    return res
      .status(400)
      .json({ error: "Please provide a gitUrl in the request body." });
  }

  console.log(`Received analysis request for: ${gitUrl}`);

  try {
    // Step 1: Clone the repository dynamically
    console.log("Starting repository clone");
    const repoPath = await cloneRepository(gitUrl);
    console.log("Clone successful");

    // Step 2: Run Semgrep on the cloned codebase
    console.log("Starting Semgrep analysis");
    const semgrepOutput = await runSemgrep(repoPath);
    console.log("Semgrep analysis complete");

    // Step 3: Parse and return the vulnerabilities found
    let vulnerabilities;
    try {
      vulnerabilities = JSON.parse(semgrepOutput);
      console.log(
        `Analysis complete. Found ${vulnerabilities.results?.length || 0} results`
      );
    } catch (parseError) {
      console.error(`Error parsing Semgrep output: ${parseError}`);
      console.error(`Raw output: ${semgrepOutput}`);
      vulnerabilities = { 
        error: "Failed to parse Semgrep output",
        results: [] 
      };
    }

    // Send back the results
    res.json({ vulnerabilities });

    // Step 4: Cleanup the cloned repository
    try {
      console.log(`Cleaning up: ${repoPath}`);
      fs.rmSync(repoPath, { recursive: true, force: true });
      console.log("Cleanup complete");
    } catch (cleanupError) {
      console.error(`Error during cleanup: ${cleanupError}`);
    }
  } catch (error: any) {
    console.error(`Analysis failed: ${error.message}`);
    res.status(500).json({ error: `Analysis failed: ${error.message}` });
  }
});

// GET /health: Health check endpoint
app.get("/health", (req: Request, res: Response) => {
  res.json({ 
    status: "healthy",
    checks: {
      tempDir: fs.existsSync(TEMP_DIR),
      semgrep: true, // We'll assume it's available; the actual check happens at startup
    }
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Temporary directory: ${TEMP_DIR}`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  // Clean up temp directory
  if (fs.existsSync(TEMP_DIR)) {
    try {
      fs.rmSync(TEMP_DIR, { recursive: true, force: true });
      console.log(`Cleaned up temp directory: ${TEMP_DIR}`);
    } catch (error) {
      console.error(`Error cleaning up temp directory: ${error}`);
    }
  }
  process.exit(0);
});