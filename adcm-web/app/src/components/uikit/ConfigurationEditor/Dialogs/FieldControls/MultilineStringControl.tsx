import { useMemo, useState } from 'react';
import CodeEditor from '@uikit/CodeEditor/CodeEditor';
import ConfigurationField from './ConfigurationField';
import { SingleSchemaDefinition } from '@models/adcm';
import { JSONPrimitive } from '@models/json';
import { prettifyJson } from '@utils/stringUtils';
import s from './ConfigurationField.module.scss';

const textTransformers: { [format: string]: (value: string) => string } = {
  json: prettifyJson,
};

interface MultilineStringControlProps {
  fieldName: string;
  value: JSONPrimitive;
  fieldSchema: SingleSchemaDefinition;
  onChange: (newValue: JSONPrimitive) => void;
}

const MultilineStringControl = ({ fieldName, value, fieldSchema, onChange }: MultilineStringControlProps) => {
  const stringValue = value as string;
  const format = fieldSchema.format ?? 'text';
  const [isFormatted, setIsFormatted] = useState(false);

  const code = useMemo(() => {
    if (!isFormatted) {
      const transformer = textTransformers[format];
      if (transformer) {
        setIsFormatted(true);
        return transformer(stringValue);
      }
    }

    return stringValue;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stringValue]);

  const handleChange = (code: string) => {
    onChange(code);
  };

  return (
    <ConfigurationField label={fieldName} fieldSchema={fieldSchema} onChange={onChange}>
      <CodeEditor
        className={s.configurationField__codeEditor}
        isSecret={fieldSchema.adcmMeta.isSecret}
        language={format}
        code={code}
        onChange={handleChange}
      />
    </ConfigurationField>
  );
};

export default MultilineStringControl;
