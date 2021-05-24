/*
 * BrowserUp Proxy
 * ___ This is the REST API for controlling the BrowserUp Proxy. The BrowserUp Proxy is a swiss army knife for automated testing that captures HTTP traffic in HAR files. It is also useful for Selenium/Cypress tests. ___ 
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.browserup.proxy_client;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;
import java.math.BigDecimal;

/**
 * PagePageTimings
 */
@javax.annotation.Generated(value = "org.openapitools.codegen.languages.JavaClientCodegen")
public class PagePageTimings {
  public static final String SERIALIZED_NAME_ON_CONTENT_LOAD = "onContentLoad";
  @SerializedName(SERIALIZED_NAME_ON_CONTENT_LOAD)
  private BigDecimal onContentLoad;

  public static final String SERIALIZED_NAME_ON_LOAD = "onLoad";
  @SerializedName(SERIALIZED_NAME_ON_LOAD)
  private BigDecimal onLoad;

  public static final String SERIALIZED_NAME_COMMENT = "comment";
  @SerializedName(SERIALIZED_NAME_COMMENT)
  private String comment;


  public PagePageTimings onContentLoad(BigDecimal onContentLoad) {
    
    this.onContentLoad = onContentLoad;
    return this;
  }

   /**
   * Get onContentLoad
   * minimum: -1
   * @return onContentLoad
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public BigDecimal getOnContentLoad() {
    return onContentLoad;
  }


  public void setOnContentLoad(BigDecimal onContentLoad) {
    this.onContentLoad = onContentLoad;
  }


  public PagePageTimings onLoad(BigDecimal onLoad) {
    
    this.onLoad = onLoad;
    return this;
  }

   /**
   * Get onLoad
   * minimum: -1
   * @return onLoad
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public BigDecimal getOnLoad() {
    return onLoad;
  }


  public void setOnLoad(BigDecimal onLoad) {
    this.onLoad = onLoad;
  }


  public PagePageTimings comment(String comment) {
    
    this.comment = comment;
    return this;
  }

   /**
   * Get comment
   * @return comment
  **/
  @javax.annotation.Nullable
  @ApiModelProperty(value = "")

  public String getComment() {
    return comment;
  }


  public void setComment(String comment) {
    this.comment = comment;
  }


  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    PagePageTimings pagePageTimings = (PagePageTimings) o;
    return Objects.equals(this.onContentLoad, pagePageTimings.onContentLoad) &&
        Objects.equals(this.onLoad, pagePageTimings.onLoad) &&
        Objects.equals(this.comment, pagePageTimings.comment);
  }

  @Override
  public int hashCode() {
    return Objects.hash(onContentLoad, onLoad, comment);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class PagePageTimings {\n");
    sb.append("    onContentLoad: ").append(toIndentedString(onContentLoad)).append("\n");
    sb.append("    onLoad: ").append(toIndentedString(onLoad)).append("\n");
    sb.append("    comment: ").append(toIndentedString(comment)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }

}

