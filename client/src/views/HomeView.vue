<template>
  <div class="main-container">
    <div class="bg-image"></div>
    <h1>us-east-1</h1>
    <v-network-graph
      v-if="data"
      ref="graph"
      :nodes="data.nodes"
      :edges="data.edges"
      :layouts="data.layouts"
      :configs="data.configs"
      :layers="layers"
    >
    </v-network-graph>
  </div>
</template>

<script setup>
import { ref, onMounted } from "vue";
import * as vNG from "v-network-graph";
import { ForceLayout } from "v-network-graph/lib/force-layout";
import GraphService from "@/services/graphService.js";

// additional layers definition
const layers = {
  worldmap: "base",
}

const graph = ref();
let data = ref();

onMounted( async () => {
  const { nodes, edges } = await GraphService.createGraphData();

  const configs = vNG.defineConfigs({
    view: {
      layoutHandler: new ForceLayout({
        positionFixedByDrag: false,
        positionFixedByClickWithAltKey: true,
      }),
    },
    node: {
      normal: {
        type: "circle",
        radius:  (node) => node?.type === "function" ? 30 : 15,
        color: (node) => node.color,
      },
      label: {
        visible: true,
        direction: "south",
        directionAutoAdjustment: true,
        fontSize: 14,
        lineHeight: 1.1,
        color: "#fff",
        margin: 8,
        text: "name",
      },
    },
  });

  data.value = { nodes, edges, configs }
});

</script>

<style lang="scss"  >
body{
  margin: 0px !important; 
}
.main-container {
  height: 100vh;
  width: 100vw;
  background-color: black;
  
  & > h1 {
    position: absolute;
    left: 86%;
    top: 92%;
    z-index: 1001;
  }
}
.actions-container{
  position: absolute;
  left: 1%;
  top: 3%;
  background-color: black;
  z-index: 100;
}

.bg-image {
  background-image: url("@/assets/us-east1.svg");
  background-repeat: no-repeat;
  background-size: 70% 20%;
  position: absolute;
  left: 43%;
  top: 62%;
  height: 100%;
  width: 100%;
  transform: scale(0.5);
  z-index: 1000;
}
</style>
