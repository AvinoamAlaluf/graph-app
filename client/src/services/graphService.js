import axios from "axios";

const getVulnerabilities = () => {
  return axios
    .get("http://localhost:3000/api/vulnerabilities")
    .then(function (response) {
      // handle success
      return response.data;
    })
    .catch(function (error) {
      // handle error
      console.error(error);
    })
    .finally(function () {
      // always executed
    });
};

const createGraphData = async () => {
  const data = await getVulnerabilities();
  let nodesCounter = 0;
  let edgeCounter = 0;
  let nodes = {};
  let edges = {};

  for (const key in data) {
    nodesCounter++;

    if (Object.hasOwnProperty.call(data, key)) {
      const value = data[key];
      nodes[`node${nodesCounter}`] = {
        id: key,
        name: getResourceShortName(key),
        color: "blue",
        type: "function",
      };

      let sourceNodeId = nodesCounter;

      value.map((findingItem) => {
        nodesCounter++;
        edgeCounter++;

        nodes[`node${nodesCounter}`] = {
          id: findingItem.FindingUniqueId,
          name: findingItem.ResourceId,
          color:
            findingItem?.Severity.toLowerCase() === "low" ? "yellow" : "red",
        };

        edges[`edge${edgeCounter}`] = {
          source: `node${sourceNodeId}`,
          target: `node${nodesCounter}`,
        };
      });
    }
  }

  return { nodes, edges };
};

const getResourceShortName = (name) => {
  const reoccurringKey = "arn:aws:lambda:us-east-1:1234567890:";
  if (!name.includes(reoccurringKey)) return name;
  return name.substring(reoccurringKey.length, name.length);
};

export default {
  getVulnerabilities,
  createGraphData,
};
