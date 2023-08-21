const PROWLER_FILE_PATH =
  "./files/prowler-output-1234567890-20230814122946.json";
const LAMBDA_FILE_PATH = "./files/resources";

const createFileStream = (filePath) => {
  const fs = require("fs");
  const readline = require("readline");

  const inputStream = fs.createReadStream(filePath);
  const rl = readline.createInterface({
    input: inputStream,
    output: process.stdout,
    terminal: false,
  });

  const line_counter = // counter IIFE function to the line number - not built it in node, just in case we want to check a specific case which is line determined
    (
      (i = 0) =>
      () =>
        ++i
    )();
  return { rl, line_counter };
};

const handleLambdaFile = async () => {
  return new Promise((resolve, reject) => {
    const { rl } = createFileStream(LAMBDA_FILE_PATH);
    const lambdasMap = {}; // used an object for O(1)

    rl.on("line", (line) => {
      try {
        lambdasMap[line.trim().toLowerCase()] = true; // avoids duplicates
      } catch (error) {
        // Handle JSON parsing errors
        console.error("Error reading resources file:", error);
        reject(error);
      }
    });

    rl.on("close", () => {
      resolve(lambdasMap);
    });
  });
};

const checkShouldSkipSavingObject = (sanitizedLine) => {
  if (sanitizedLine?.includes(`"ServiceName":`)) {
    // checking type
    if (sanitizedLine !== `"ServiceName": "lambda",`) {
      return true;
    }
  } else if (sanitizedLine?.includes(`"Status":`)) {
    // checking status
    if (sanitizedLine !== `"Status": "FAIL",`) {
      return true;
    }
  }
  return false;
};

const getResourcesVulnerabilities = async () => {
  return new Promise(async (resolve, reject) => {
    const lambdasMap = await handleLambdaFile();
    const { rl, line_counter } = createFileStream(PROWLER_FILE_PATH);

    let isSaveLines = false;
    let savedLinesStr = "";
    const lambdaFunctionsWithFailStatus = {}; // object as map

    const resetSavedLinesVars = () => {
      // inner helper to rest vars
      isSaveLines = false;
      savedLinesStr = "";
    };

    rl.on("line", (line, lineNumber = line_counter()) => {
      try {
        let sanitizedLine = line?.trim();

        if (sanitizedLine === "},{") {
          // end and start of object - save lines from now on
          if (savedLinesStr?.length) {
            // finished going through an object that needs to be parsed
            savedLinesStr = `{${savedLinesStr}}`;
            try {
              const jsonObject = JSON.parse(savedLinesStr);
              if (
                jsonObject.ResourceArn?.length &&
                !!lambdasMap[jsonObject.ResourceArn.trim().toLowerCase()]
              ) {
                // only save resources relvant to the lambdas resource map
                let sanitizedKey = jsonObject.ResourceArn.trim().toLowerCase();
                lambdaFunctionsWithFailStatus?.[sanitizedKey]
                  ? lambdaFunctionsWithFailStatus[sanitizedKey].push(jsonObject)
                  : (lambdaFunctionsWithFailStatus[sanitizedKey] = [
                      jsonObject,
                    ]);
              }
            } catch (error) {
              console.error("Error parsing JSON:", error);
            }
          }
          resetSavedLinesVars();
          isSaveLines = true;
        } else if (sanitizedLine !== "},{" && isSaveLines) {
          savedLinesStr += line;
          if (checkShouldSkipSavingObject(sanitizedLine)) {
            resetSavedLinesVars();
          }
        } else if (lineNumber === 1 && !isSaveLines && sanitizedLine === "[{") {
          // first object
          isSaveLines = true;
        }
      } catch (error) {
        // Handle JSON parsing errors
        console.error("Error parsing JSON:", error);
      }
    });

    rl.on("close", () => {
      //handling the last object edge case
      let sanitizedSavedLinesStr = savedLinesStr.trim();
      if (
        sanitizedSavedLinesStr?.includes(`"Status": "FAIL"`) &&
        sanitizedSavedLinesStr?.includes(`"ServiceName": "lambda"`)
      ) {
        if (
          sanitizedSavedLinesStr.endsWith("}]") ||
          sanitizedSavedLinesStr.endsWith("},")
        ) {
          sanitizedSavedLinesStr = sanitizedSavedLinesStr.substring(
            0,
            sanitizedSavedLinesStr.length - 2
          );
        }

        if (sanitizedSavedLinesStr.startsWith("{")) {
          sanitizedSavedLinesStr = sanitizedSavedLinesStr.substring(
            1,
            sanitizedSavedLinesStr.length
          );
        }
        sanitizedSavedLinesStr = `{${sanitizedSavedLinesStr}}`;
        try {
          const jsonObject = JSON.parse(sanitizedSavedLinesStr);
          if (jsonObject.ResourceArn?.length) {
            // only save resources relvant to the lambdas resource map
            let sanitizedKey = jsonObject.ResourceArn.trim().toLowerCase();
            lambdaFunctionsWithFailStatus?.[sanitizedKey]
              ? lambdaFunctionsWithFailStatus[sanitizedKey].push(jsonObject)
              : (lambdaFunctionsWithFailStatus[sanitizedKey] = [jsonObject]);
          }
        } catch (error) {
          console.error("Error parsing JSON:", error);
        }
      }

      resolve(lambdaFunctionsWithFailStatus);
    });
  });
};

module.exports = { getResourcesVulnerabilities };
