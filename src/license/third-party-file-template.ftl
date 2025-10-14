<#function licenseFormat licenses>
    <#assign result = ""/>
    <#list licenses as license>
        <#assign result = result + " (" +license + ")"/>
    </#list>
    <#return result>
</#function>
<#function artifactFormat p>
    <#if p.name?index_of('Unnamed') &gt; -1>
        <#return p.artifactId + " (" + p.groupId + ":" + p.artifactId + ":" + p.version + " - " + (p.url!"no url defined") + ")">
    <#else>
        <#return p.name + " (" + p.groupId + ":" + p.artifactId + ":" + p.version + " - " + (p.url!"no url defined") + ")">
    </#if>
</#function>
List of ${dependencyMap?size} third-party dependencies (auto-generated on ${.now?date?iso_utc} with License Maven Plugin):

<#list dependencyMap as e>
<#assign project = e.getKey()/>
<#assign licenses = e.getValue()/>
* ${licenseFormat(licenses)} ${artifactFormat(project)}
</#list>
