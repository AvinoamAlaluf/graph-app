<template>
  <div class="hello">
    {{ data }}
  </div>
</template>


<script>
import { onMounted, defineComponent } from 'vue';
import GraphService from "@/services/graphService.js"

export default defineComponent({
    async setup() {
    
    const data = await GraphService.getVulnerabilities()
    console.log(data);
      // .then(res => res);
      // console.log(mock);
        return {
          data
        }
    }
})
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="scss">
h3 {
  margin: 40px 0 0;
}
ul {
  list-style-type: none;
  padding: 0;
}
li {
  display: inline-block;
  margin: 0 10px;
}
a {
  color: #42b983;
}
</style>
